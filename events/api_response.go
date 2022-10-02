package events

import (
	"crypto/rsa"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gford1000-serverless/util/sign"
)

// NewGatewayProxyResponder returns an initialised responder
func NewGatewayProxyResponder(signingPrivateKey *rsa.PrivateKey) *GatewayProxyResponder {
	return &GatewayProxyResponder{
		k: signingPrivateKey,
		h: make(map[string]string),
	}
}

// GatewayProxyResponder provides a standard mechanism to create instances
// of APIGatewayProxyResponse.
// The instance can optionally sign the body of the response when a private
// key is provided
type GatewayProxyResponder struct {
	k *rsa.PrivateKey
	h map[string]string
}

// AddHeader allows a single header to be added
func (g *GatewayProxyResponder) AddHeader(header, value string) {
	g.h[header] = value
}

// NewErrorAPIResponse returns a standard body for errors
func (g *GatewayProxyResponder) NewErrorAPIResponse(status int, e error) *events.APIGatewayProxyResponse {
	type errorMsg struct {
		Msg string `json:"error"`
	}

	body := &errorMsg{
		Msg: e.Error(),
	}

	var jsonBody []byte

	if g.k != nil {
		sb, err := sign.NewSignedBody(body, g.k)
		if err != nil {
			panic(err)
		}

		jsonBody, err = json.Marshal(sb)
		if err != nil {
			panic(err)
		}
	} else {
		var err error
		jsonBody, err = json.Marshal(body)
		if err != nil {
			panic(err)
		}
	}

	return &events.APIGatewayProxyResponse{
		Headers:    g.h,
		StatusCode: status,
		Body:       string(jsonBody),
	}
}

// NewAPIResponse formats the response for the API Gateway
func (g *GatewayProxyResponder) NewAPIResponse(status int, body any) (*events.APIGatewayProxyResponse, error) {

	var jsonBody []byte

	if g.k != nil {
		sb, err := sign.NewSignedBody(body, g.k)
		if err != nil {
			return g.NewErrorAPIResponse(500, err), nil
		}

		jsonBody, err = json.Marshal(sb)
		if err != nil {
			return g.NewErrorAPIResponse(500, err), nil
		}
	} else {
		var err error
		jsonBody, err = json.Marshal(body)
		if err != nil {
			return g.NewErrorAPIResponse(500, err), nil
		}
	}

	return &events.APIGatewayProxyResponse{
		Headers:    g.h,
		StatusCode: status,
		Body:       string(jsonBody),
	}, nil
}
