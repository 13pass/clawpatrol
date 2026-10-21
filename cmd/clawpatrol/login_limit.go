package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Login attempts are limited by failures, in three kinds of bucket:
//
//   - one per known username, so a password cannot be guessed from
//     many addresses at once;
//   - one shared by every unknown username, so spraying random names
//     costs no memory and blocks no real account;
//   - one per client address. Behind a reverse proxy every request
//     shares the proxy's address (forwarded headers are not trusted),
//     so this limit is generous: it acts as a global one there.
//
// A blocked attempt is refused before any bcrypt work. Success clears
// the username's bucket, never the address's: a valid account must
// not reset the count of an address guessing other accounts.
const (
	loginFailureWindow       = 15 * time.Minute
	loginBlockDuration       = 15 * time.Minute
	loginMaxFailuresPerUser  = 10
	loginMaxFailuresPerAddr  = 30
	loginLimiterPruneAtSize  = 4096
	loginUnknownUserBucket   = "user:\x00unknown"
	loginUserBucketPrefix    = "user:"
	loginAddressBucketPrefix = "addr:"
)

type loginFailures struct {
	count        int
	windowStart  time.Time
	blockedUntil time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginFailures
	now     func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{buckets: map[string]*loginFailures{}, now: time.Now}
}

// loginBuckets returns the bucket keys an attempt counts against. A
// username that has no account shares the unknown bucket.
func loginBuckets(username string, userExists bool, remoteAddr string) []string {
	user := loginUnknownUserBucket
	if userExists {
		user = loginUserBucketPrefix + username
	}
	return []string{user, loginAddressBucketPrefix + loginClientAddress(remoteAddr)}
}

func loginClientAddress(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func loginBucketLimit(key string) int {
	if strings.HasPrefix(key, loginAddressBucketPrefix) {
		return loginMaxFailuresPerAddr
	}
	return loginMaxFailuresPerUser
}

// blocked reports how long until every bucket of an attempt admits it
// again; zero means the attempt may proceed.
func (l *loginLimiter) blocked(keys []string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for _, k := range keys {
		if b := l.buckets[k]; b != nil && now.Before(b.blockedUntil) {
			if d := b.blockedUntil.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait
}

// recordFailure counts a failed attempt against every bucket, and
// blocks a bucket that reaches its limit within the window. It
// returns the buckets this failure blocked.
func (l *loginLimiter) recordFailure(keys []string) []string {
	var blockedNow []string
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.buckets) >= loginLimiterPruneAtSize {
		l.pruneLocked(now)
	}
	for _, k := range keys {
		b := l.buckets[k]
		if b == nil || now.Sub(b.windowStart) > loginFailureWindow {
			b = &loginFailures{windowStart: now}
			l.buckets[k] = b
		}
		b.count++
		if b.count >= loginBucketLimit(k) {
			b.blockedUntil = now.Add(loginBlockDuration)
			b.count = 0
			b.windowStart = now
			blockedNow = append(blockedNow, k)
		}
	}
	return blockedNow
}

// recordSuccess clears a username's bucket after a correct password.
func (l *loginLimiter) recordSuccess(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, loginUserBucketPrefix+username)
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.windowStart) > loginFailureWindow && !now.Before(b.blockedUntil) {
			delete(l.buckets, k)
		}
	}
}

// loginLimits is shared by every dashboard listener of the gateway.
func (g *Gateway) loginLimits() *loginLimiter {
	g.loginLimitOnce.Do(func() {
		if g.loginLimit == nil {
			g.loginLimit = newLoginLimiter()
		}
	})
	return g.loginLimit
}

// loginRetryAfterSeconds rounds a block up to whole seconds for the
// Retry-After header.
func loginRetryAfterSeconds(wait time.Duration) int {
	return int((wait + time.Second - 1) / time.Second)
}
