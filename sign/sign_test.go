package sign

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestNewSignedBody(t *testing.T) {

	type testObject struct {
		Value string `json:"value"`
	}

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var msg = "Hello World"

	sb, err := NewSignedBody(
		&testObject{
			Value: msg,
		},
		k,
	)
	if err != nil {
		t.Fatal(err)
	}

	var v testObject
	err = VerifySignedBody(sb, &k.PublicKey, &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Value != msg {
		t.Fatal("Verified object does not have the correct details")
	}
}
