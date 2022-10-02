package events

import (
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
)

// AddHeaders provides access to apply headers
type AddHeaders func() map[string]string

// NewErrorAPIResponse returns a standard body for errors
func NewErrorAPIResponse(status int, f AddHeaders, e error) *events.APIGatewayProxyResponse {
	type errorMsg struct {
		Msg string `json:"error"`
	}

	stringBody, _ := json.Marshal(
		&errorMsg{
			Msg: e.Error(),
		})

	return &events.APIGatewayProxyResponse{
		Headers:    f(),
		StatusCode: status,
		Body:       string(stringBody),
	}
}

// NewAPIResponse formats the response for the API Gateway
func NewAPIResponse(status int, f AddHeaders, body interface{}) (*events.APIGatewayProxyResponse, error) {
	stringBody, err := json.Marshal(body)
	if err != nil {
		return NewErrorAPIResponse(500, f, err), nil
	}

	return &events.APIGatewayProxyResponse{
		Headers:    f(),
		StatusCode: status,
		Body:       string(stringBody),
	}, nil
}
