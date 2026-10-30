//! Receipt payload, envelope, emit/verify — §3, §4, §8.
//!
//! Mirrors the canonical Python reference (raucle/provenance.py)
//! byte-for-byte: same JOSE header (incl. the `"raucle/v1": "provenance"`
//! tag), same payload field set, string-typed model/tool/corpus,
//! sha256:-prefixed hashes, and the same content-addressed id
//! (`"sha256:" + hex(sha256(jws))`).

use crate::canonical::canonical_encode;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const JWS_TYP: &str = "provenance-receipt/v1";
const ISS: &str = "raucle-detect/provenance";

#[derive(Debug)]
pub struct ProvError(pub String);
impl std::fmt::Display for ProvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ProvError {}

fn err<T>(s: impl Into<String>) -> Result<T, ProvError> {
    Err(ProvError(s.into()))
}

fn known_field(k: &str) -> bool {
    matches!(
        k,
        "iss" | "typ"
            | "iat"
            | "agent_id"
            | "agent_key_id"
            | "operation"
            | "parents"
            | "input_hash"
            | "output_hash"
            | "taint"
            | "ruleset_hash"
            | "guardrail_verdict"
            | "model"
            | "tool"
            | "corpus"
            | "tenant"
    )
}

fn valid_operation(op: &str) -> bool {
    matches!(
        op,
        "user_input"
            | "model_call"
            | "tool_call"
            | "retrieval"
            | "guardrail_scan"
            | "agent_handoff"
            | "sanitisation"
            | "merge"
    )
}

/// A signed receipt.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub jws: String,
    /// The parsed payload object.
    pub payload: Value,
    /// Content-addressed id (§8): "sha256:" + hex SHA-256 of the JWS.
    pub id: String,
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64u_decode(s: &str) -> Result<Vec<u8>, ProvError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| ProvError(format!("base64: {e}")))
}

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex_encode(&h.finalize())
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn str_field<'a>(obj: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    obj.get(k).and_then(|v| v.as_str())
}

/// Per-operation required fields (§4). Lenient like the Python reference:
/// presence only, not value shapes.
fn check_op_fields(obj: &Map<String, Value>, op: &str) -> Result<(), ProvError> {
    let has = |k: &str| str_field(obj, k).map(|s| !s.is_empty()).unwrap_or(false);

    if op == "guardrail_scan" && !has("guardrail_verdict") {
        return err("guardrail_scan requires guardrail_verdict (§4)");
    }
    if op == "guardrail_scan" && !has("ruleset_hash") {
        return err("guardrail_scan requires ruleset_hash (§4)");
    }
    if op == "model_call" && !has("model") {
        return err("model_call requires model (§4)");
    }
    if (op == "tool_call" || op == "sanitisation") && !has("tool") {
        return err(format!("{op} requires tool (§4)"));
    }
    if (op == "retrieval" || op == "sanitisation") && !has("corpus") {
        return err(format!("{op} requires corpus (§4)"));
    }
    Ok(())
}

/// Validate a payload object against §4. Lenient where the Python
/// reference is lenient: enforces structural invariants (required
/// fields per operation, parent rules, typ literal), not value shapes.
pub fn validate_payload(p: &Value) -> Result<(), ProvError> {
    let obj = match p.as_object() {
        Some(o) => o,
        None => return err("payload must be an object"),
    };

    for k in obj.keys() {
        if !known_field(k) && !k.starts_with("x_") {
            return err(format!("reserved/unknown field: {k} (§14)"));
        }
    }

    if str_field(obj, "typ") != Some(JWS_TYP) {
        return err(format!("payload typ must be {JWS_TYP:?}"));
    }

    let op = str_field(obj, "operation").unwrap_or("");
    if !valid_operation(op) {
        return err(format!("unknown operation: {op}"));
    }

    check_op_fields(obj, op)?;

    let parent_count = obj
        .get("parents")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if op == "user_input" && parent_count > 0 {
        return err("user_input must have no parents");
    }
    if op != "user_input" && parent_count == 0 {
        return err(format!("{op} requires at least one parent"));
    }

    // §4.2/§4.3.1: parents and taint MUST be sorted in UTF-16 code-unit order
    // and unique. A strictly-increasing check enforces both at once.
    for name in ["parents", "taint"] {
        if let Some(arr) = obj.get(name).and_then(|v| v.as_array()) {
            for w in arr.windows(2) {
                let (a, b) = (w[0].as_str().unwrap_or(""), w[1].as_str().unwrap_or(""));
                if a.encode_utf16().cmp(b.encode_utf16()) != std::cmp::Ordering::Less {
                    return err(format!(
                        "{name} must be sorted in UTF-16 code-unit order and unique (§4.3.1)"
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Build the canonical payload object from caller-supplied fields,
/// injecting the constant `iss`/`typ` and sorting parents+taint, exactly
/// as Python's `ProvenanceReceipt.payload()` does.
fn normalise_payload(payload: &Value) -> Result<Value, ProvError> {
    let src = payload
        .as_object()
        .ok_or_else(|| ProvError("payload must be an object".into()))?;
    let mut obj: Map<String, Value> = src.clone();
    obj.insert("iss".into(), json!(ISS));
    obj.insert("typ".into(), json!(JWS_TYP));

    // Sort parents + taint to match the canonical reference.
    for key in ["parents", "taint"] {
        if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
            let mut v: Vec<String> = arr
                .iter()
                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                .collect();
            // UTF-16 code-unit order (JCS), matching the canonical reference.
            v.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            obj.insert(key.into(), json!(v));
        }
    }
    Ok(Value::Object(obj))
}

/// Emit (sign) a payload object.
pub fn emit(payload: &Value, signing_key: &SigningKey) -> Result<Receipt, ProvError> {
    let payload = normalise_payload(payload)?;
    validate_payload(&payload)?;

    let kid = payload
        .get("agent_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProvError("missing agent_key_id".into()))?;

    let header = json!({
        "alg": "EdDSA",
        "typ": JWS_TYP,
        "kid": kid,
        "crit": ["raucle/v1"],
        "raucle/v1": "provenance",
    });

    let header_b = canonical_encode(&header).map_err(|e| ProvError(e.0))?;
    let payload_b = canonical_encode(&payload).map_err(|e| ProvError(e.0))?;
    let signing_input = format!("{}.{}", b64u(&header_b), b64u(&payload_b));
    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    let jws = format!("{}.{}", signing_input, b64u(&sig.to_bytes()));
    let id = format!("sha256:{}", sha256_hex(jws.as_bytes()));
    Ok(Receipt { jws, payload, id })
}

/// Verify a Compact JWS against a public key and parse it.
pub fn verify(jws: &str, verifying_key: &VerifyingKey) -> Result<Receipt, ProvError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return err("JWS must have three segments");
    }
    let (header_b, payload_b, sig_b) = (parts[0], parts[1], parts[2]);

    let header: Value = serde_json::from_slice(&b64u_decode(header_b)?)
        .map_err(|e| ProvError(format!("header parse: {e}")))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return err("unsupported alg");
    }
    if header.get("typ").and_then(|v| v.as_str()) != Some(JWS_TYP) {
        return err("unexpected typ");
    }
    let crit_ok = header
        .get("crit")
        .and_then(|v| v.as_array())
        .map(|a| a.len() == 1 && a[0].as_str() == Some("raucle/v1"))
        .unwrap_or(false);
    if !crit_ok {
        return err("crit must be exactly ['raucle/v1']");
    }
    if header.get("raucle/v1").and_then(|v| v.as_str()) != Some("provenance") {
        return err("header 'raucle/v1' must be 'provenance'");
    }
    if let Some(obj) = header.as_object() {
        for k in obj.keys() {
            if !matches!(k.as_str(), "alg" | "typ" | "kid" | "crit" | "raucle/v1") {
                return err("unexpected JOSE header key");
            }
        }
    }

    // Canonical byte-equality (spec v1 §4.3, matches the Python reference): the
    // signature binds the on-wire bytes, but a non-canonical header (unsorted
    // keys / extra whitespace) would still verify without re-encoding and
    // comparing — admitting byte-different receipts for the same content.
    if canonical_encode(&header).map_err(|e| ProvError(e.0))? != b64u_decode(header_b)? {
        return err("JOSE header is not canonical JSON (JCS)");
    }

    let sig_bytes = b64u_decode(sig_b)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| ProvError(format!("sig: {e}")))?;
    let signing_input = format!("{}.{}", header_b, payload_b);
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| ProvError("signature invalid".into()))?;

    let payload_bytes = b64u_decode(payload_b)?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| ProvError(format!("payload parse: {e}")))?;
    if canonical_encode(&payload).map_err(|e| ProvError(e.0))? != payload_bytes {
        return err("JWS payload is not canonical JSON (JCS)");
    }

    validate_payload(&payload)?;

    if header.get("kid").and_then(|v| v.as_str())
        != payload.get("agent_key_id").and_then(|v| v.as_str())
    {
        return err("header.kid != payload.agent_key_id (§3)");
    }

    let id = format!("sha256:{}", sha256_hex(jws.as_bytes()));
    Ok(Receipt {
        jws: jws.to_string(),
        payload,
        id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn base_payload() -> Value {
        json!({
            "iat": 1700000001,
            "agent_id": "agent:test.scanner",
            "agent_key_id": "k_test01",
            "operation": "user_input",
            "parents": [],
            "taint": [],
        })
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn emit_verify_roundtrip() {
        let sk = key();
        let r = emit(&base_payload(), &sk).unwrap();
        assert!(verify(&r.jws, &sk.verifying_key()).is_ok());
    }

    // Live bug #2 (§8.10): a correctly-signed JWS whose payload bytes are valid
    // JSON but not JCS-canonical (here: a re-serialised pretty form) must be
    // rejected — otherwise byte-different receipts verify for the same content.
    #[test]
    fn verify_rejects_non_canonical_payload() {
        let sk = key();
        let r = emit(&base_payload(), &sk).unwrap();
        let parts: Vec<&str> = r.jws.split('.').collect();
        let payload_bytes = b64u_decode(parts[1]).unwrap();
        let value: Value = serde_json::from_slice(&payload_bytes).unwrap();
        // serde_json::to_vec_pretty produces valid JSON with whitespace → not canonical.
        let noncanon = serde_json::to_vec_pretty(&value).unwrap();
        let signing_input = format!("{}.{}", parts[0], b64u(&noncanon));
        let sig: Signature = sk.sign(signing_input.as_bytes());
        let jws = format!("{}.{}", signing_input, b64u(&sig.to_bytes()));
        assert!(verify(&jws, &sk.verifying_key()).is_err());
    }
}
