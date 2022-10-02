package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var allowedAlgo = "PSS-SHA256"

var errSNil = errors.New("SignedBody must be provided")
var errNoPublicKey = errors.New("PublicKey must be provided")
var errNoPrivateKey = errors.New("PrivateKey must be provided")
var errNoV = errors.New("object for body must be provided")
var errInvalidAlgo = fmt.Errorf("algo must be '%s'", allowedAlgo)

// SignedBody provides a uniform, signed object that can be
// returned by services that need to provide proof of work
type SignedBody struct {
	Signature string `json:"signature"`
	Algo      string `json:"algo"`
	Body      string `json:"body"`
}

func (s SignedBody) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// NewSignedBody returns an instance of SignedBody, marshalling the
// provided object to JSON and then signing with the key
func NewSignedBody(v any, privateKey *rsa.PrivateKey) (*SignedBody, error) {

	if v == nil {
		return nil, errNoV
	}

	if privateKey == nil {
		return nil, errNoPrivateKey
	}

	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	msgHash := sha256.New()
	_, err = msgHash.Write(b)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return nil, err
	}

	return &SignedBody{
		Signature: base64.URLEncoding.EncodeToString(signature),
		Body:      base64.URLEncoding.EncodeToString(b),
		Algo:      allowedAlgo,
	}, nil
}

// VerifySignedBody will populate v with the contents of Body, if the
// signature is verified with regards to the public key provided
func VerifySignedBody(s *SignedBody, publicKey *rsa.PublicKey, v any) error {

	if s == nil {
		return errSNil
	}
	if publicKey == nil {
		return errNoPublicKey
	}
	if v == nil {
		return errNoV
	}
	if s.Algo != allowedAlgo {
		return errInvalidAlgo
	}

	signature, err := base64.URLEncoding.DecodeString(s.Signature)
	if err != nil {
		return err
	}

	b, err := base64.URLEncoding.DecodeString(s.Body)
	if err != nil {
		return err
	}

	msgHash := sha256.New()
	_, err = msgHash.Write(b)
	if err != nil {
		return err
	}
	msgHashSum := msgHash.Sum(nil)

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}
