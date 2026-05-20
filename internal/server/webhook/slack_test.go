package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"
)

// signSlackTest builds a (signature, timestamp) pair for testing
// matching the recipe VerifySlackSignature checks.
func signSlackTest(secret string, body []byte, at time.Time) (string, string) {
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	return SlackSignaturePrefix + hex.EncodeToString(mac.Sum(nil)), ts
}

func TestVerifySlackSignature_ValidAndStale(t *testing.T) {
	secret := "shh"
	body := []byte(`{"type":"url_verification","challenge":"x"}`)

	sig, ts := signSlackTest(secret, body, time.Now())
	if !VerifySlackSignature(secret, sig, ts, body) {
		t.Error("fresh sig rejected; want accept")
	}

	// Stale timestamp (>5 minutes old) → reject.
	sig, ts = signSlackTest(secret, body, time.Now().Add(-10*time.Minute))
	if VerifySlackSignature(secret, sig, ts, body) {
		t.Error("stale sig accepted; want reject")
	}

	// Wrong secret → reject.
	wrongSig, ts := signSlackTest("other-secret", body, time.Now())
	if VerifySlackSignature(secret, wrongSig, ts, body) {
		t.Error("wrong-secret sig accepted; want reject")
	}

	// Malformed prefix → reject.
	_, ts = signSlackTest(secret, body, time.Now())
	if VerifySlackSignature(secret, "badprefix-deadbeef", ts, body) {
		t.Error("malformed prefix accepted; want reject")
	}

	// Empty inputs → reject.
	if VerifySlackSignature(secret, "", ts, body) {
		t.Error("empty sig accepted; want reject")
	}
}

func TestVerifySlackSignature_BodyTamper(t *testing.T) {
	secret := "shh"
	body := []byte(`{"x":1}`)
	sig, ts := signSlackTest(secret, body, time.Now())
	tampered := []byte(`{"x":2}`)
	if VerifySlackSignature(secret, sig, ts, tampered) {
		t.Error("tampered body still verified; want reject")
	}
	_ = fmt.Sprintf // keep fmt import alive when test panics print fields
}
