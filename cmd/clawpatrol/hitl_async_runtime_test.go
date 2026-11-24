package main

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/config/match"
)

func TestHITLAsyncBodySkipReason(t *testing.T) {
	const maxBody = 4
	cases := []struct {
		name string
		in   hitlAsyncOperationInput
		want string
	}{
		{"complete body", hitlAsyncOperationInput{MatchReq: &match.Request{}, RawBody: []byte("abcd")}, ""},
		{"no body", hitlAsyncOperationInput{MatchReq: &match.Request{}}, ""},
		{"truncated", hitlAsyncOperationInput{MatchReq: &match.Request{}, Truncated: true}, "body truncated"},
		{"not captured", hitlAsyncOperationInput{MatchReq: &match.Request{BodyNotCaptured: true}}, "body not captured"},
		{"no match request", hitlAsyncOperationInput{}, "body not captured"},
		{"truncated wins over too large", hitlAsyncOperationInput{MatchReq: &match.Request{}, Truncated: true, RawBody: []byte("abcde")}, "body truncated"},
		{"too large", hitlAsyncOperationInput{MatchReq: &match.Request{}, RawBody: []byte("abcde")}, "body over the async size limit"},
	}
	for _, c := range cases {
		if got := hitlAsyncBodySkipReason(c.in, maxBody); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
