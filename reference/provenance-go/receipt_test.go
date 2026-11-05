package provenance

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	critKey     = "raucle/v1"
	testModelV1 = "test-model-v1"
)

func parseEd25519PubPEM(p string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 key")
	}
	return pk, nil
}

func basePayload() Payload {
	return Payload{
		Iat:        1700000001,
		AgentID:    "agent:test.scanner",
		AgentKeyID: "k_test01",
		Operation:  "user_input",
		Parents:    nil,
		InputHash:  "sha256:f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef",
		Taint:      []string{"untrusted_user"},
	}
}

func mustKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestEmitVerifyRoundtrip(t *testing.T) {
	pub, priv := mustKeys(t)
	r, err := Emit(basePayload(), priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Verify(r.JWS, pub)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Payload.AgentID != "agent:test.scanner" {
		t.Fatalf("agent_id mismatch: %s", parsed.Payload.AgentID)
	}
	if parsed.ID != r.ID || !strings.HasPrefix(r.ID, "sha256:") {
		t.Fatalf("id mismatch/prefix: %s", parsed.ID)
	}
}

func TestVerifyRejectsDifferentKey(t *testing.T) {
	_, priv := mustKeys(t)
	otherPub, _ := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	if _, err := Verify(r.JWS, otherPub); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestVerifyRejectsWrongAlg(t *testing.T) {
	pub, priv := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	parts := strings.Split(r.JWS, ".")
	badHeader, _ := json.Marshal(map[string]any{
		"alg": "HS256", "typ": jwsTyp, "kid": "k_test01",
		"crit": []string{critKey}, critKey: "provenance",
	})
	hb := base64.RawURLEncoding.EncodeToString(badHeader)
	if _, err := Verify(hb+"."+parts[1]+"."+parts[2], pub); err == nil {
		t.Fatal("expected alg rejection")
	}
}

func TestVerifyRequiresCrit(t *testing.T) {
	pub, priv := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	parts := strings.Split(r.JWS, ".")
	badHeader, _ := json.Marshal(map[string]any{
		"alg": "EdDSA", "typ": jwsTyp, "kid": "k_test01",
		"crit": []string{}, critKey: "provenance",
	})
	hb := base64.RawURLEncoding.EncodeToString(badHeader)
	if _, err := Verify(hb+"."+parts[1]+"."+parts[2], pub); err == nil {
		t.Fatal("expected crit rejection")
	}
}

func TestNonUserInputRequiresParents(t *testing.T) {
	_, priv := mustKeys(t)
	p := basePayload()
	p.Operation = "model_call"
	p.Model = testModelV1
	if _, err := Emit(p, priv); err == nil {
		t.Fatal("expected parent requirement")
	}
}

func TestRejectsUnknownPayloadField(t *testing.T) {
	if _, err := payloadFromMap(map[string]any{
		"typ": typ, "operation": "user_input", "rogue": true,
	}); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestRejectsMissingTyp(t *testing.T) {
	if _, err := payloadFromMap(map[string]any{
		"operation": "user_input",
	}); err == nil {
		t.Fatal("expected typ rejection")
	}
}

func TestChainTopoAndClosure(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "model_call"
	p2.Parents = []string{r1.ID}
	p2.Model = testModelV1
	r2, _ := Emit(p2, priv)
	c, err := BuildChain([]Receipt{r1, r2})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(c.Receipts))
	}
}

func TestChainRejectsTopoBreak(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "model_call"
	p2.Parents = []string{r1.ID}
	p2.Model = testModelV1
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r2, r1}); err == nil {
		t.Fatal("expected topo violation")
	}
}

func TestChainRejectsSilentTaintLoss(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "model_call"
	p2.Parents = []string{r1.ID}
	p2.Taint = nil
	p2.Model = testModelV1
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r1, r2}); err == nil {
		t.Fatal("expected taint monotonicity violation")
	}
}

func TestSanitisationRemovesTagViaCorpus(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "sanitisation"
	p2.Parents = []string{r1.ID}
	p2.Taint = nil
	p2.Tool = "redactor:pii-v1"
	p2.Corpus = "removed:untrusted_user"
	p2.OutputHash = "sha256:e54b74eb9192b48055c48d2062bffdd23469ef7d70f960ff1293a47f86c8eba2"
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r1, r2}); err != nil {
		t.Fatal(err)
	}
}

func TestSanitisationUndeclaredDropFails(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "sanitisation"
	p2.Parents = []string{r1.ID}
	p2.Taint = nil
	p2.Tool = "redactor:pii-v1"
	p2.Corpus = "removed:something_else"
	p2.OutputHash = "sha256:e54b74eb9192b48055c48d2062bffdd23469ef7d70f960ff1293a47f86c8eba2"
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r1, r2}); err == nil {
		t.Fatal("expected sanitisation taint mismatch")
	}
}

// TestCanonicalParity locks the canonical-JSON output to the exact
// bytes the Python + TS reference encoders produce for the same object.
func TestCanonicalParity(t *testing.T) {
	got, err := canonicalEncode(map[string]any{
		"iss": "x", "iat": 1, "parents": []any{"a", "b"},
		"taint": []any{"a_t", "z_t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"iat":1,"iss":"x","parents":["a","b"],"taint":["a_t","z_t"]}`
	if string(got) != want {
		t.Fatalf("canonical mismatch:\n got=%s\nwant=%s", got, want)
	}
}

// ── shared cross-language conformance: the published test vectors ──

type vectorFile struct {
	PublicKeyPEM string `json:"public_key_pem"`
	FixedSeedHex string `json:"fixed_seed_hex"`
	Vectors      []struct {
		Name            string `json:"name"`
		ExpectedJWS     string `json:"expected_jws"`
		ExpectedReceipt string `json:"expected_receipt_hash"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) (vectorFile, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "spec", "provenance", "v1", "test-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	pub, err := parseEd25519PubPEM(vf.PublicKeyPEM)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	return vf, pub
}

// payloadFromJWS decodes (without verifying) the payload object from a
// compact JWS into a Payload, so we can re-emit it from the fixed seed.
func payloadFromJWS(t *testing.T, jws string) Payload {
	t.Helper()
	parts := strings.Split(jws, ".")
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(pb, &m); err != nil {
		t.Fatal(err)
	}
	p, err := payloadFromMap(m)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSpecVectors(t *testing.T) {
	vf, pub := loadVectors(t)
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	seed, err := hexDecode(vf.FixedSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			// (a) Verify the published JWS + recompute its content id.
			r, err := Verify(v.ExpectedJWS, pub)
			if err != nil {
				t.Fatalf("verify failed: %v", err)
			}
			if r.ID != v.ExpectedReceipt {
				t.Fatalf("receipt_hash mismatch:\n got=%s\nwant=%s", r.ID, v.ExpectedReceipt)
			}
			// (b) Re-emit from the fixed seed: the Go-produced JWS and id
			//     MUST be byte-identical to the published vector.
			p := payloadFromJWS(t, v.ExpectedJWS)
			emitted, err := Emit(p, priv)
			if err != nil {
				t.Fatalf("emit failed: %v", err)
			}
			if emitted.JWS != v.ExpectedJWS {
				t.Fatalf("emitted JWS differs:\n got=%s\nwant=%s", emitted.JWS, v.ExpectedJWS)
			}
			if emitted.ID != v.ExpectedReceipt {
				t.Fatalf("emitted id differs:\n got=%s\nwant=%s", emitted.ID, v.ExpectedReceipt)
			}
		})
	}
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var b int
		_, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		out[i] = byte(b)
	}
	return out, nil
}

// TestVerifyRejectsNonCanonicalPayload pins live bug #2 (§8.10): a JWS whose
// payload bytes are valid JSON but not JCS-canonical (here: pretty-printed with
// whitespace) must be rejected even when correctly signed — otherwise
// byte-different receipts for the same logical content would verify.
func TestVerifyRejectsNonCanonicalPayload(t *testing.T) {
	pub, priv := mustKeys(t)
	r, err := Emit(basePayload(), priv)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(r.JWS, ".")
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var pm map[string]any
	if err := json.Unmarshal(payloadBytes, &pm); err != nil {
		t.Fatal(err)
	}
	// Re-encode with insignificant whitespace → same object, non-canonical bytes.
	noncanon, _ := json.MarshalIndent(pm, "", "  ")
	pb := base64.RawURLEncoding.EncodeToString(noncanon)
	signingInput := parts[0] + "." + pb
	sig := ed25519.Sign(priv, []byte(signingInput))
	jws := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := Verify(jws, pub); err == nil {
		t.Fatal("expected non-canonical payload rejection")
	}
}

// TestVerifyRejectsNonCanonicalHeader is the header-side counterpart.
func TestVerifyRejectsNonCanonicalHeader(t *testing.T) {
	pub, priv := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	parts := strings.Split(r.JWS, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hm map[string]any
	if err := json.Unmarshal(headerBytes, &hm); err != nil {
		t.Fatal(err)
	}
	noncanon, _ := json.MarshalIndent(hm, "", " ")
	hb := base64.RawURLEncoding.EncodeToString(noncanon)
	signingInput := hb + "." + parts[1]
	sig := ed25519.Sign(priv, []byte(signingInput))
	jws := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := Verify(jws, pub); err == nil {
		t.Fatal("expected non-canonical header rejection")
	}
}
