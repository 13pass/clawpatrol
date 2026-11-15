package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDeniedResponseCarriesTheRequestID(t *testing.T) {
	var buf bytes.Buffer
	writeDenied(&buf, "deleting is not allowed", "0194-abc")
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(requestIDHeader) != "0194-abc" {
		t.Errorf("status %d, %s = %q", resp.StatusCode, requestIDHeader, resp.Header.Get(requestIDHeader))
	}
	if !strings.HasPrefix(string(body), "deleting is not allowed\n") || !strings.HasSuffix(string(body), "Claw Patrol request: 0194-abc\n") {
		t.Errorf("body = %q", body)
	}
}
