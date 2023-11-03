package generic

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// RoundTripFunc is a function that will be called to fulfill and http request.
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip executes the round trip, calling the underlying function.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls.
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

// JSONResponse sets up a basic http.Response with an object in the body of the response.
func JSONResponse(t *testing.T, code int, body any) *http.Response {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))

	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(&buf),
		Header: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
}
