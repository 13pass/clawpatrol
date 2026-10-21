package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeLoginClock struct{ t time.Time }

func (c *fakeLoginClock) now() time.Time { return c.t }

func newTestLoginLimiter() (*loginLimiter, *fakeLoginClock) {
	clock := &fakeLoginClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	l := newLoginLimiter()
	l.now = clock.now
	return l, clock
}

func TestLoginLimiterBlocksKnownUserAcrossAddresses(t *testing.T) {
	l, clock := newTestLoginLimiter()
	for i := 0; i < loginMaxFailuresPerUser; i++ {
		l.recordFailure(loginBuckets("root", true, fmt.Sprintf("192.0.2.%d:1234", i)))
	}
	if wait := l.blocked(loginBuckets("root", true, "198.51.100.1:1")); wait != loginBlockDuration {
		t.Fatalf("root from a fresh address: wait = %s, want %s", wait, loginBlockDuration)
	}
	if wait := l.blocked(loginBuckets("alice", true, "198.51.100.1:1")); wait != 0 {
		t.Fatalf("another user is blocked too: wait = %s", wait)
	}
	clock.t = clock.t.Add(loginBlockDuration)
	if wait := l.blocked(loginBuckets("root", true, "198.51.100.1:1")); wait != 0 {
		t.Fatalf("root still blocked after the block expired: %s", wait)
	}
}

func TestLoginLimiterUnknownUsersShareOneBucket(t *testing.T) {
	l, _ := newTestLoginLimiter()
	for i := 0; i < loginMaxFailuresPerUser; i++ {
		l.recordFailure(loginBuckets(fmt.Sprintf("guess-%d", i), false, fmt.Sprintf("192.0.2.%d:1", i)))
	}
	if wait := l.blocked(loginBuckets("guess-new", false, "198.51.100.1:1")); wait == 0 {
		t.Fatal("unknown usernames are not limited as a group")
	}
	if wait := l.blocked(loginBuckets("root", true, "198.51.100.1:1")); wait != 0 {
		t.Fatalf("a name spray blocked root: %s", wait)
	}
	if n := len(l.buckets); n > 1+loginMaxFailuresPerUser {
		t.Fatalf("%d buckets after a spray of %d names", n, loginMaxFailuresPerUser)
	}
}

func TestLoginLimiterBlocksAddressAcrossUsernames(t *testing.T) {
	l, _ := newTestLoginLimiter()
	const addr = "192.0.2.7:4444"
	var blockedNow []string
	for i := 0; i < loginMaxFailuresPerAddr; i++ {
		blockedNow = l.recordFailure(loginBuckets(fmt.Sprintf("user-%d", i), true, addr))
	}
	if len(blockedNow) != 1 || blockedNow[0] != loginAddressBucketPrefix+"192.0.2.7" {
		t.Fatalf("last failure blocked %v, want the address bucket", blockedNow)
	}
	if wait := l.blocked(loginBuckets("someone", true, "192.0.2.7:5555")); wait == 0 {
		t.Fatal("address not blocked (port must not matter)")
	}
}

func TestLoginLimiterSuccessClearsUserButNotAddress(t *testing.T) {
	l, _ := newTestLoginLimiter()
	const addr = "192.0.2.9:1"
	for i := 0; i < loginMaxFailuresPerUser-1; i++ {
		l.recordFailure(loginBuckets("root", true, addr))
	}
	l.recordSuccess("root")
	if b := l.buckets[loginUserBucketPrefix+"root"]; b != nil {
		t.Fatalf("root bucket survived a success: %+v", b)
	}
	if b := l.buckets[loginAddressBucketPrefix+"192.0.2.9"]; b == nil || b.count != loginMaxFailuresPerUser-1 {
		t.Fatalf("address bucket = %+v, want its failures kept", b)
	}
}

func TestLoginLimiterWindowExpires(t *testing.T) {
	l, clock := newTestLoginLimiter()
	for i := 0; i < loginMaxFailuresPerUser-1; i++ {
		l.recordFailure(loginBuckets("root", true, "192.0.2.1:1"))
	}
	clock.t = clock.t.Add(loginFailureWindow + time.Second)
	l.recordFailure(loginBuckets("root", true, "192.0.2.1:1"))
	if wait := l.blocked(loginBuckets("root", true, "192.0.2.1:1")); wait != 0 {
		t.Fatal("failures from an expired window still counted")
	}
}

func TestLoginLimiterPrunesStaleBuckets(t *testing.T) {
	l, clock := newTestLoginLimiter()
	for i := 0; i < loginLimiterPruneAtSize; i++ {
		l.recordFailure([]string{fmt.Sprintf("%s192.0.2.%d", loginAddressBucketPrefix, i)})
	}
	clock.t = clock.t.Add(loginFailureWindow + time.Second)
	l.recordFailure(loginBuckets("root", true, "198.51.100.1:1"))
	if n := len(l.buckets); n != 2 {
		t.Fatalf("%d buckets after pruning, want the 2 fresh ones", n)
	}
}

func TestDashboardLoginRateLimited(t *testing.T) {
	w := newUsersTestMux(t)
	limiter, _ := newTestLoginLimiter()
	w.g.loginLimit = limiter

	for i := 0; i < loginMaxFailuresPerUser; i++ {
		if rw := postLogin(t, w, "username=alice&password=wrong-password-000"); rw.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, want 401", i, rw.Code)
		}
	}
	rw := postLogin(t, w, "username=alice&password="+usersTestMemberPassword)
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password while blocked: status %d, want 429", rw.Code)
	}
	if got, err := strconv.Atoi(rw.Header().Get("Retry-After")); err != nil || got <= 0 {
		t.Fatalf("Retry-After = %q", rw.Header().Get("Retry-After"))
	}
	if !strings.Contains(rw.Body.String(), "too many failed attempts") {
		t.Fatalf("body lacks the rate-limit message")
	}
	if got := sessionUserFromResponse(t, w, rw); got != "" {
		t.Fatalf("session minted while blocked for %q", got)
	}
	if rw := postLogin(t, w, "password="+usersTestRootPassword); rw.Code != http.StatusFound {
		t.Fatalf("root login from the same test address: %d, want 302 (address limit is %d)", rw.Code, loginMaxFailuresPerAddr)
	}
}

func TestMePasswordRateLimited(t *testing.T) {
	w := newUsersTestMux(t)
	limiter, _ := newTestLoginLimiter()
	w.g.loginLimit = limiter
	h := w.handler()
	member := sessionCookieFor(t, w, "alice")
	for i := 0; i < loginMaxFailuresPerUser; i++ {
		serveAs(t, h, member, http.MethodPost, "/api/me/password", `{"current":"wrong-passphrase-0000","new":"brand-new-passphrase-1234"}`)
	}
	rw := serveAs(t, h, member, http.MethodPost, "/api/me/password",
		`{"current":"`+usersTestMemberPassword+`","new":"brand-new-passphrase-1234"}`)
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("password change while blocked = %d, want 429", rw.Code)
	}
}
