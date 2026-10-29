package main

// Per-user notification channels (doc/notification-channels.md): each
// dashboard user sets where their approval prompts go, and proves it
// with a code sent there before the channel is used.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const (
	channelCodeDigits      = 6
	channelCodeTTL         = 10 * time.Minute
	channelCodeMaxAttempts = 5
	// channelSendInterval is the least time between two messages a user
	// has the gateway send (codes and tests): the sender is shared.
	channelSendInterval    = time.Minute
	channelSendTimeout     = 15 * time.Second
	channelRequestMaxBytes = 8 << 10
)

var errNoUserChannel = errors.New("no notification channel is set")

// channelSendMu serializes the throttle check, the send and its record,
// so parallel requests cannot each pass the throttle.
var channelSendMu sync.Mutex

type userChannel struct {
	Kind          string
	Target        string
	Secret        string
	VerifiedNs    int64
	CodeHash      string
	CodeExpiresNs int64
	CodeAttempts  int
	SentNs        int64
	UpdatedNs     int64
}

// channelStatus is what a browser sees of a channel: never its secret.
type channelStatus struct {
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	Verified   bool   `json:"verified"`
	VerifiedNs int64  `json:"verified_ns,omitempty"`
	UpdatedNs  int64  `json:"updated_ns"`
}

func (c userChannel) status() channelStatus {
	return channelStatus{Kind: c.Kind, Target: c.Target, Verified: c.VerifiedNs > 0, VerifiedNs: c.VerifiedNs, UpdatedNs: c.UpdatedNs}
}

func (c userChannel) runtime() runtime.UserChannel {
	return runtime.UserChannel{Target: c.Target, Secret: c.Secret}
}

func lookupUserChannel(db *sql.DB, username string) (userChannel, error) {
	var c userChannel
	err := db.QueryRow(
		`SELECT kind, target, secret, verified_ns, code_hash, code_expires_ns, code_attempts, sent_ns, updated_ns
		 FROM dashboard_user_channels WHERE username = ?`, username,
	).Scan(&c.Kind, &c.Target, &c.Secret, &c.VerifiedNs, &c.CodeHash, &c.CodeExpiresNs, &c.CodeAttempts, &c.SentNs, &c.UpdatedNs)
	if errors.Is(err, sql.ErrNoRows) {
		return c, errNoUserChannel
	}
	return c, err
}

// saveUnverifiedUserChannel stores a channel with a fresh code; it
// replaces any earlier channel, verified or not.
func saveUnverifiedUserChannel(db *sql.DB, username string, c userChannel, codeHash string, now time.Time) error {
	_, err := db.Exec(
		`INSERT INTO dashboard_user_channels (username, kind, target, secret, verified_ns, code_hash, code_expires_ns, code_attempts, sent_ns, updated_ns)
		 VALUES (?, ?, ?, ?, 0, ?, ?, 0, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   kind = excluded.kind, target = excluded.target, secret = excluded.secret,
		   verified_ns = 0, code_hash = excluded.code_hash, code_expires_ns = excluded.code_expires_ns,
		   code_attempts = 0, sent_ns = excluded.sent_ns, updated_ns = excluded.updated_ns`,
		username, c.Kind, c.Target, c.Secret, codeHash, now.Add(channelCodeTTL).UnixNano(), now.UnixNano(), now.UnixNano(),
	)
	return err
}

func setUserChannelCode(db *sql.DB, username, codeHash string, now time.Time) error {
	_, err := db.Exec(
		`UPDATE dashboard_user_channels SET code_hash = ?, code_expires_ns = ?, code_attempts = 0, sent_ns = ? WHERE username = ?`,
		codeHash, now.Add(channelCodeTTL).UnixNano(), now.UnixNano(), username,
	)
	return err
}

func markUserChannelVerified(db *sql.DB, username string, now time.Time) error {
	_, err := db.Exec(
		`UPDATE dashboard_user_channels SET verified_ns = ?, code_hash = '', code_expires_ns = 0, code_attempts = 0, updated_ns = ? WHERE username = ?`,
		now.UnixNano(), now.UnixNano(), username,
	)
	return err
}

// claimUserChannelAttempt uses up one code attempt in a single
// statement, so parallel guesses cannot share one slot.
func claimUserChannelAttempt(db *sql.DB, username string) (bool, error) {
	res, err := db.Exec(
		`UPDATE dashboard_user_channels SET code_attempts = code_attempts + 1 WHERE username = ? AND code_attempts < ?`,
		username, channelCodeMaxAttempts,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func setUserChannelSent(db *sql.DB, username string, now time.Time) error {
	_, err := db.Exec(`UPDATE dashboard_user_channels SET sent_ns = ? WHERE username = ?`, now.UnixNano(), username)
	return err
}

func deleteUserChannel(db *sql.DB, username string) error {
	_, err := db.Exec(`DELETE FROM dashboard_user_channels WHERE username = ?`, username)
	return err
}

func allUserChannelStatuses(db *sql.DB) (map[string]channelStatus, error) {
	rows, err := db.Query(`SELECT username, kind, target, verified_ns, updated_ns FROM dashboard_user_channels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]channelStatus{}
	for rows.Next() {
		var username string
		var c userChannel
		if err := rows.Scan(&username, &c.Kind, &c.Target, &c.VerifiedNs, &c.UpdatedNs); err != nil {
			return nil, err
		}
		out[username] = c.status()
	}
	return out, rows.Err()
}

// profileOwners lists the users who own profile, each with their
// verified channel when a declared credential can deliver it.
func (g *Gateway) profileOwners(profile string) []runtime.ProfileOwner {
	if g.db == nil || profile == "" {
		return nil
	}
	rows, err := g.db.Query(
		`SELECT p.username, COALESCE(c.kind, ''), COALESCE(c.target, ''), COALESCE(c.secret, ''), COALESCE(c.verified_ns, 0)
		 FROM dashboard_user_profiles p
		 JOIN dashboard_users u ON u.username = p.username
		 LEFT JOIN dashboard_user_channels c ON c.username = p.username
		 WHERE p.profile = ? ORDER BY p.username`, profile,
	)
	if err != nil {
		log.Printf("profile owners of %s: %v", profile, err)
		return nil
	}
	defer rows.Close()
	var out []runtime.ProfileOwner
	for rows.Next() {
		var o runtime.ProfileOwner
		var c userChannel
		if err := rows.Scan(&o.Username, &c.Kind, &c.Target, &c.Secret, &c.VerifiedNs); err != nil {
			log.Printf("profile owners of %s: %v", profile, err)
			return nil
		}
		if c.VerifiedNs > 0 {
			if cred, _, ok := g.channelSender(c.Kind); ok {
				o.Credential, o.Channel = cred, c.runtime()
			}
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		log.Printf("profile owners of %s: %v", profile, err)
	}
	return out
}

func newChannelCode() (string, string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", "", err
	}
	code := fmt.Sprintf("%0*d", channelCodeDigits, n.Int64())
	return code, hashChannelCode(code), nil
}

func hashChannelCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// channelSender is the declared credential that delivers channels of
// kind (a credential plugin type), the first by name if several do.
func (g *Gateway) channelSender(kind string) (string, runtime.HITLChannelSender, bool) {
	policy := g.Policy()
	if policy == nil {
		return "", nil, false
	}
	names := make([]string, 0, len(policy.Credentials))
	for name := range policy.Credentials {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ent := policy.Credentials[name]
		if ent == nil || ent.Plugin == nil || ent.Plugin.Type != kind {
			continue
		}
		if s, ok := ent.Body.(runtime.HITLChannelSender); ok {
			return name, s, true
		}
	}
	return "", nil, false
}

// channelKinds lists the kinds a user may pick: those a declared
// credential can deliver.
func (g *Gateway) channelKinds() []string {
	policy := g.Policy()
	seen := map[string]bool{}
	out := []string{}
	if policy == nil {
		return out
	}
	for _, ent := range policy.Credentials {
		if ent == nil || ent.Plugin == nil || seen[ent.Plugin.Type] {
			continue
		}
		if _, ok := ent.Body.(runtime.HITLChannelSender); ok {
			seen[ent.Plugin.Type] = true
			out = append(out, ent.Plugin.Type)
		}
	}
	sort.Strings(out)
	return out
}

func (g *Gateway) sendChannelText(ctx context.Context, c userChannel, text string) error {
	cred, sender, ok := g.channelSender(c.Kind)
	if !ok {
		return fmt.Errorf("no %s credential is configured to send with", c.Kind)
	}
	ctx, cancel := context.WithTimeout(ctx, channelSendTimeout)
	defer cancel()
	return sender.SendChannelText(ctx, g.secrets, cred, c.runtime(), text)
}

// channelOwner is the signed-in database user; tailnet operators have
// no row to hang a channel on.
func channelOwner(rw http.ResponseWriter, r *http.Request) (string, bool) {
	p, ok := principalFromContext(r.Context())
	if !ok || p.Kind != principalDashboardPassword {
		http.Error(rw, "only dashboard accounts have a notification channel", http.StatusBadRequest)
		return "", false
	}
	setAuditTarget(r, p.Owner)
	return p.Owner, true
}

func decodeChannelRequest(rw http.ResponseWriter, r *http.Request, body any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, channelRequestMaxBytes)).Decode(body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// throttled refuses a send within channelSendInterval of the last one.
func throttled(rw http.ResponseWriter, c userChannel, now time.Time) bool {
	wait := time.Unix(0, c.SentNs).Add(channelSendInterval).Sub(now)
	if wait <= 0 {
		return false
	}
	rw.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	http.Error(rw, "a message was sent less than a minute ago; try again shortly", http.StatusTooManyRequests)
	return true
}

func codeMessage(code string) string {
	return "clawpatrol: your verification code is " + code + ". Type it on the dashboard's Account page within " +
		strconv.Itoa(int(channelCodeTTL.Minutes())) + " minutes. If you did not ask for it, ignore this message."
}

func (w *webMux) apiMyChannel(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	out := map[string]any{"channel": nil, "kinds": w.g.channelKinds()}
	if p, ok := principalFromContext(r.Context()); ok && p.Kind == principalDashboardPassword {
		c, err := lookupUserChannel(w.g.db, p.Owner)
		switch {
		case err == nil:
			out["channel"] = c.status()
		case !errors.Is(err, errNoUserChannel):
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(rw, out)
}

// apiMyChannelSet replaces the caller's channel with an unverified one
// and sends it a code. The old channel is kept if the send fails.
func (w *webMux) apiMyChannelSet(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	username, ok := channelOwner(rw, r)
	if !ok {
		return
	}
	channelSendMu.Lock()
	defer channelSendMu.Unlock()
	var body struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Secret string `json:"secret"`
	}
	if !decodeChannelRequest(rw, r, &body) {
		return
	}
	c := userChannel{Kind: body.Kind, Target: strings.TrimSpace(body.Target), Secret: strings.TrimSpace(body.Secret)}
	_, sender, ok := w.g.channelSender(c.Kind)
	if !ok {
		http.Error(rw, "the gateway cannot send to "+strconv.Quote(c.Kind)+" channels", http.StatusBadRequest)
		return
	}
	if err := sender.ValidateChannel(c.runtime()); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now()
	old, err := lookupUserChannel(w.g.db, username)
	if err != nil && !errors.Is(err, errNoUserChannel) {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if throttled(rw, old, now) {
		return
	}
	code, hash, err := newChannelCode()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := w.g.sendChannelText(r.Context(), c, codeMessage(code)); err != nil {
		http.Error(rw, "could not send the code: "+err.Error(), http.StatusBadGateway)
		return
	}
	if err := saveUnverifiedUserChannel(w.g.db, username, c, hash, now); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// apiMyChannelResend sends a new code to the caller's unverified
// channel, so a Teams user need not paste the webhook URL again.
func (w *webMux) apiMyChannelResend(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	username, ok := channelOwner(rw, r)
	if !ok {
		return
	}
	channelSendMu.Lock()
	defer channelSendMu.Unlock()
	c, ok := w.myChannel(rw, username)
	if !ok {
		return
	}
	if c.VerifiedNs > 0 {
		http.Error(rw, "the channel is already verified", http.StatusBadRequest)
		return
	}
	now := time.Now()
	if throttled(rw, c, now) {
		return
	}
	code, hash, err := newChannelCode()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := w.g.sendChannelText(r.Context(), c, codeMessage(code)); err != nil {
		http.Error(rw, "could not send the code: "+err.Error(), http.StatusBadGateway)
		return
	}
	if err := setUserChannelCode(w.g.db, username, hash, now); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) apiMyChannelVerify(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	username, ok := channelOwner(rw, r)
	if !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeChannelRequest(rw, r, &body) {
		return
	}
	c, ok := w.myChannel(rw, username)
	if !ok {
		return
	}
	now := time.Now()
	switch {
	case c.VerifiedNs > 0:
		http.Error(rw, "the channel is already verified", http.StatusBadRequest)
		return
	case c.CodeHash == "" || now.UnixNano() > c.CodeExpiresNs:
		http.Error(rw, "the code has expired; send a new one", http.StatusBadRequest)
		return
	}
	claimed, err := claimUserChannelAttempt(w.g.db, username)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if !claimed {
		http.Error(rw, "too many wrong codes; send a new one", http.StatusTooManyRequests)
		return
	}
	got := hashChannelCode(strings.TrimSpace(body.Code))
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.CodeHash)) != 1 {
		http.Error(rw, "wrong code", http.StatusForbidden)
		return
	}
	if err := markUserChannelVerified(w.g.db, username, now); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) apiMyChannelTest(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	username, ok := channelOwner(rw, r)
	if !ok {
		return
	}
	channelSendMu.Lock()
	defer channelSendMu.Unlock()
	c, ok := w.myChannel(rw, username)
	if !ok {
		return
	}
	if c.VerifiedNs == 0 {
		http.Error(rw, "verify the channel first", http.StatusBadRequest)
		return
	}
	now := time.Now()
	if throttled(rw, c, now) {
		return
	}
	text := "clawpatrol: test message for " + username + ". Approval prompts for your agents arrive here."
	if err := w.g.sendChannelText(r.Context(), c, text); err != nil {
		http.Error(rw, "could not send: "+err.Error(), http.StatusBadGateway)
		return
	}
	if err := setUserChannelSent(w.g.db, username, now); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) apiMyChannelDelete(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	username, ok := channelOwner(rw, r)
	if !ok {
		return
	}
	if err := deleteUserChannel(w.g.db, username); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// apiUsersChannelClear lets an admin remove a user's channel; only the
// user can set one.
func (w *webMux) apiUsersChannelClear(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if !decodeChannelRequest(rw, r, &body) {
		return
	}
	setAuditTarget(r, auditUsername(body.Username))
	if err := deleteUserChannel(w.g.db, body.Username); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

func (w *webMux) myChannel(rw http.ResponseWriter, username string) (userChannel, bool) {
	c, err := lookupUserChannel(w.g.db, username)
	if errors.Is(err, errNoUserChannel) {
		http.Error(rw, err.Error(), http.StatusNotFound)
		return c, false
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return c, false
	}
	return c, true
}
