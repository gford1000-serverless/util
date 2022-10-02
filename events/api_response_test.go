package events

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/gford1000-serverless/util/sign"
)

func TestGatewayProxyResponder(t *testing.T) {

	type testObject struct {
		Value string `json:"value"`
	}

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var msg = "Hello World"

	g := NewGatewayProxyResponder(k)
	g.AddHeader("Content-Type", "application/json")

	r, err := g.NewAPIResponse(200, &testObject{
		Value: msg,
	})
	if err != nil {
		t.Fatal(err)
	}

	var sb sign.SignedBody
	err = json.Unmarshal([]byte(r.Body), &sb)
	if err != nil {
		t.Fatal(err)
	}

	var v testObject
	err = sign.VerifySignedBody(&sb, &k.PublicKey, &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Value != msg {
		if err != nil {
			t.Fatal("Unpack failure")
		}
	}
}

func TestGatewayProxyResponderNoKey(t *testing.T) {

	type testObject struct {
		Value string `json:"value"`
	}

	var msg = "Hello World"

	g := NewGatewayProxyResponder(nil)
	g.AddHeader("Content-Type", "application/json")

	r, err := g.NewAPIResponse(200, &testObject{
		Value: msg,
	})
	if err != nil {
		t.Fatal(err)
	}

	var v testObject
	err = json.Unmarshal([]byte(r.Body), &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Value != msg {
		if err != nil {
			t.Fatal("Unpack failure")
		}
	}
}
