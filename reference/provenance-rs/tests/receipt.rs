use ed25519_dalek::SigningKey;
use raucle_provenance::{build_chain, canonical_encode, emit, verify};
use serde_json::{json, Value};

fn key() -> SigningKey {
    let mut secret = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

fn base_payload() -> Value {
    json!({
        "iat": 1700000001,
        "agent_id": "agent:test.scanner",
        "agent_key_id": "k_test01",
        "operation": "user_input",
        "parents": [],
        "input_hash": "sha256:f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef",
        "taint": ["untrusted_user"],
    })
}

#[test]
fn emit_verify_roundtrip() {
    let sk = key();
    let r = emit(&base_payload(), &sk).unwrap();
    let parsed = verify(&r.jws, &sk.verifying_key()).unwrap();
    assert_eq!(
        parsed.payload.get("agent_id").unwrap().as_str().unwrap(),
        "agent:test.scanner"
    );
    assert_eq!(parsed.id, r.id);
    assert!(r.id.starts_with("sha256:"));
    assert_eq!(
        parsed.payload.get("iss").unwrap().as_str().unwrap(),
        "raucle-detect/provenance"
    );
    assert_eq!(
        parsed.payload.get("typ").unwrap().as_str().unwrap(),
        "provenance-receipt/v1"
    );
}

#[test]
fn verify_rejects_different_key() {
    let sk = key();
    let other = key();
    let r = emit(&base_payload(), &sk).unwrap();
    assert!(verify(&r.jws, &other.verifying_key()).is_err());
}

#[test]
fn verify_rejects_wrong_alg() {
    use base64::Engine;
    let sk = key();
    let r = emit(&base_payload(), &sk).unwrap();
    let parts: Vec<&str> = r.jws.split('.').collect();
    let bad_header = serde_json::to_vec(&json!({
        "alg": "HS256", "typ": "provenance-receipt/v1",
        "kid": "k_test01", "crit": ["raucle/v1"], "raucle/v1": "provenance"
    }))
    .unwrap();
    let hb = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bad_header);
    let jws = format!("{}.{}.{}", hb, parts[1], parts[2]);
    assert!(verify(&jws, &sk.verifying_key()).is_err());
}

#[test]
fn non_user_input_requires_parents() {
    let sk = key();
    let mut p = base_payload();
    p["operation"] = json!("model_call");
    p["parents"] = json!([]);
    p["model"] = json!("test-model-v1");
    assert!(emit(&p, &sk).is_err());
}

#[test]
fn rejects_reserved_unknown_field() {
    let sk = key();
    let mut p = base_payload();
    p["rogue"] = json!(true);
    assert!(emit(&p, &sk).is_err());
}

#[test]
fn chain_topo_and_closure() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("model_call");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!(["untrusted_user"]);
    p2["model"] = json!("test-model-v1");
    let r2 = emit(&p2, &sk).unwrap();
    let c = build_chain(vec![r1, r2]).unwrap();
    assert_eq!(c.receipts.len(), 2);
}

#[test]
fn chain_rejects_topo_break() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("model_call");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!(["untrusted_user"]);
    p2["model"] = json!("test-model-v1");
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r2, r1]).is_err());
}

#[test]
fn chain_rejects_silent_taint_loss() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("model_call");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!([]);
    p2["model"] = json!("test-model-v1");
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r1, r2]).is_err());
}

#[test]
fn sanitisation_removes_tag_via_corpus() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("sanitisation");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!([]);
    p2["tool"] = json!("redactor:pii-v1");
    p2["corpus"] = json!("removed:untrusted_user");
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r1, r2]).is_ok());
}

#[test]
fn sanitisation_undeclared_drop_fails() {
    let sk = key();
    let r1 = emit(&base_payload(), &sk).unwrap();
    let mut p2 = base_payload();
    p2["operation"] = json!("sanitisation");
    p2["parents"] = json!([r1.id]);
    p2["taint"] = json!([]);
    p2["tool"] = json!("redactor:pii-v1");
    p2["corpus"] = json!("removed:something_else");
    let r2 = emit(&p2, &sk).unwrap();
    assert!(build_chain(vec![r1, r2]).is_err());
}

#[test]
fn canonical_parity() {
    let got = canonical_encode(&json!({
        "iss": "x", "iat": 1, "parents": ["a", "b"], "taint": ["a_t", "z_t"]
    }))
    .unwrap();
    let want = r#"{"iat":1,"iss":"x","parents":["a","b"],"taint":["a_t","z_t"]}"#;
    assert_eq!(String::from_utf8(got).unwrap(), want);
}

// ── shared cross-language conformance: the published test vectors ──

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn b64u_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

#[test]
fn spec_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/spec/provenance/v1/test-vectors.json"
    );
    let raw = std::fs::read_to_string(path).expect("read vectors");
    // The vectors file deliberately contains a lone UTF-16 surrogate escape
    // ("\ud800", the `invalid_lone_surrogate` must_reject vector). Rust strings
    // are valid UTF-8 by construction, so serde_json refuses to parse the file
    // at all — which is exactly the rejection §4.3.4 mandates, enforced one
    // layer earlier than in the other ports. Neutralise lone-surrogate escapes
    // (a high escape not followed by a low one, or a bare low one) so the rest
    // of the vectors load; `must_reject` vectors are skipped below.
    let raw = neutralise_lone_surrogate_escapes(&raw);
    let vf: Value = serde_json::from_str(&raw).unwrap();

    let seed = hex_to_bytes(vf["fixed_seed_hex"].as_str().unwrap());
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let sk = SigningKey::from_bytes(&seed_arr);
    let vk = sk.verifying_key();

    let vectors = vf["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());

    let mut checked = 0;
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        if v["must_reject"].as_bool() == Some(true) {
            // Rejection-only vectors carry no JWS to re-emit. The lone-surrogate
            // case is unrepresentable in a Rust `String`, so rejection is
            // structural here (serde refuses the input before our code runs).
            continue;
        }
        let expected_jws = v["expected_jws"].as_str().unwrap();
        let expected_hash = v["expected_receipt_hash"].as_str().unwrap();

        // (a) Verify the published JWS + recompute its content id.
        let r =
            verify(expected_jws, &vk).unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));
        assert_eq!(r.id, expected_hash, "{name}: receipt_hash mismatch");

        // (b) Re-emit from the fixed seed; the Rust JWS + id MUST be
        //     byte-identical to the published vector.
        let payload_b64 = expected_jws.split('.').nth(1).unwrap();
        let payload: Value = serde_json::from_slice(&b64u_decode(payload_b64)).unwrap();
        let emitted =
            emit(&payload, &sk).unwrap_or_else(|e| panic!("{name}: emit failed: {e}"));
        assert_eq!(emitted.jws, expected_jws, "{name}: emitted JWS differs");
        assert_eq!(emitted.id, expected_hash, "{name}: emitted id differs");
        checked += 1;
    }
    assert!(checked > 0, "no emit/verify vectors were exercised");
}

/// Replace lone UTF-16 surrogate escapes (e.g. `\ud800` not part of a valid
/// high+low pair) with `\uFFFD` so serde_json can load the vectors file.
/// Valid surrogate *pairs* are left untouched.
fn neutralise_lone_surrogate_escapes(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 5 < bytes.len() && bytes[i + 1] == b'u' {
            let hex = &raw[i + 2..i + 6];
            if let Ok(cu) = u16::from_str_radix(hex, 16) {
                let is_high = (0xD800..=0xDBFF).contains(&cu);
                let is_low = (0xDC00..=0xDFFF).contains(&cu);
                if is_high {
                    // Valid only if immediately followed by a low-surrogate escape.
                    let next_ok = i + 11 < bytes.len()
                        && bytes[i + 6] == b'\\'
                        && bytes[i + 7] == b'u'
                        && u16::from_str_radix(&raw[i + 8..i + 12], 16)
                            .map(|n| (0xDC00..=0xDFFF).contains(&n))
                            .unwrap_or(false);
                    if next_ok {
                        out.push_str(&raw[i..i + 12]);
                        i += 12;
                        continue;
                    }
                    out.push_str("\\uFFFD");
                    i += 6;
                    continue;
                }
                if is_low {
                    // A low surrogate reached here is unpaired (paired ones are
                    // consumed with their high half above).
                    out.push_str("\\uFFFD");
                    i += 6;
                    continue;
                }
            }
        }
        // Copy one UTF-8 character (not byte) to stay on char boundaries.
        let ch_len = raw[i..].chars().next().map(char::len_utf8).unwrap_or(1);
        out.push_str(&raw[i..i + ch_len]);
        i += ch_len;
    }
    out
}
