package mws

import (
	"encoding/base64"
	"testing"
)

func TestDecodeJWTField(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	hdr := `{"typ":"JWT","alg":"ES256","kid":"access-key-x"}`
	pl := `{"sub":"projects/p/serviceAccounts/sa","exp":1893456000}`
	jwt := b64(hdr) + "." + b64(pl) + "." + b64("sig-bytes")
	body := []byte(`{"jwt":"` + jwt + `"}`)

	gotH, gotP, ok := decodeJWTField(body)
	if !ok {
		t.Fatal("decodeJWTField ok=false, want true")
	}
	if gotH != hdr {
		t.Errorf("header = %q, want %q", gotH, hdr)
	}
	if gotP != pl {
		t.Errorf("payload = %q, want %q", gotP, pl)
	}

	// A body without a jwt field is not a token exchange → ok=false.
	if _, _, ok := decodeJWTField([]byte(`{"metadata":{"name":"roll-1"}}`)); ok {
		t.Error("decodeJWTField on non-jwt body ok=true, want false")
	}
}
