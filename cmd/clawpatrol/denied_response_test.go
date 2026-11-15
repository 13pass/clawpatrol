package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeniedResponseCarriesTheRequestID(t *testing.T) {
	var buf bytes.Buffer
	writeDenied(&buf, "deleting is not allowed", "", "0194-abc")
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

func TestDeniedResponseCarriesTheRuleLink(t *testing.T) {
	link := requestRuleLink("https://gw.example.test/", "0194-abc")
	if link != "https://gw.example.test/#/request/0194-abc?rule" {
		t.Fatalf("link = %q", link)
	}
	if requestRuleLink("", "0194-abc") != "" {
		t.Error("a link without a public URL")
	}
	var buf bytes.Buffer
	writeDenied(&buf, "no", "https://gw.example.test/", "0194-abc")
	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get(ruleLinkHeader) != link || !strings.Contains(string(body), link) ||
		!strings.HasSuffix(string(body), "Claw Patrol request: 0194-abc\n") {
		t.Errorf("%s = %q, body = %q", ruleLinkHeader, resp.Header.Get(ruleLinkHeader), body)
	}
}

func TestAcceptedResponseCarriesTheRuleLink(t *testing.T) {
	rr := httptest.NewRecorder()
	writeHITLOperationAccepted(rr, HITLOperation{ID: "op1", State: HITLOperationStatePendingApproval}, "https://gw.example.test", "0194-abc")
	if rr.Header().Get(requestIDHeader) != "0194-abc" || rr.Header().Get(ruleLinkHeader) != "https://gw.example.test/#/request/0194-abc?rule" {
		t.Errorf("headers = %v", rr.Header())
	}
	if !strings.Contains(rr.Body.String(), `"rule_link":"https://gw.example.test/#/request/0194-abc?rule"`) {
		t.Errorf("body = %s", rr.Body.String())
	}
}
