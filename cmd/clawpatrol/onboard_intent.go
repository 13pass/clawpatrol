package main

// Join intents: the dashboard's "Agent prompt" for adding a device.
//
// An operator opens Add device and picks a profile; the dashboard
// creates an intent and renders a prompt an LLM agent can follow on
// the new device (`clawpatrol join --intent <id> …`). The prompt may
// end up in provider logs and transcripts, so the intent grants
// nothing by itself:
//
//   - it binds the first device-flow session started with it, and a
//     second start cancels it, so a leaked prompt shows up as a
//     conflict instead of a second device;
//   - the profile is the one the operator picked, whatever the CLI
//     asks for;
//   - approval is still the operator's click, made in the Add device
//     window after comparing the code the agent reports, and a join
//     that would replace an existing device needs replace=true.
//
// Several devices can share one machine (one per OS account, each on
// its own profile), so the prompt has the agent name the device
// <machine>-<account> with --hostname, which an intent join requires.
// The gateway lowercases it, so the same machine and account give the
// same name on every join and a rejoin replaces the old device.
//
// An unused intent lives while the Add device window polls it, up to
// joinIntentMaxAge: closing the window cancels it, and a window that
// stops polling lets it lapse.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	// joinIntentIDBytes is the entropy of an intent ID. The ID is not a
	// credential, but it must not be guessable either: a guessed ID
	// would let a stranger cancel an operator's pending join.
	joinIntentIDBytes = 18
	// joinIntentRetention keeps a used intent readable after its
	// session expired, so the modal can show the final state.
	joinIntentRetention = 2 * onboardSessionTTL
	// joinIntentIdle is how long an unused intent outlives the last
	// status poll from the window that shows its prompt. Browsers slow
	// or freeze timers in background tabs, so it allows long gaps.
	joinIntentIdle = 10 * time.Minute
	// joinIntentMaxAge caps an unused intent however long its window
	// stays open: the prompt may sit in an agent provider's logs.
	joinIntentMaxAge  = time.Hour
	maxDeviceNameLen  = 63
	maxJoinIntentBody = 4 << 10
)

// deviceNamePattern is what an intent join accepts as a device name.
var deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func validDeviceName(s string) bool {
	return len(s) <= maxDeviceNameLen && deviceNamePattern.MatchString(s)
}

type joinIntentState string

const (
	joinIntentWaiting  joinIntentState = "waiting"  // no device has started a join yet
	joinIntentPending  joinIntentState = "pending"  // a device waits for approval
	joinIntentApproved joinIntentState = "approved" // approved, device not yet set up
	joinIntentJoined   joinIntentState = "joined"   // the device received its configuration
	joinIntentRejected joinIntentState = "rejected" // the operator rejected or cancelled it
	joinIntentFailed   joinIntentState = "failed"   // setting the device up failed after approval
	joinIntentConflict joinIntentState = "conflict" // a second device tried to use it
	joinIntentExpired  joinIntentState = "expired"
)

type joinIntent struct {
	id       string
	creator  string // dashboard principal that created it
	profile  string
	created  time.Time
	seen     time.Time // last status poll; an unused intent lapses joinIntentIdle after it
	session  *onboardSession
	rejected bool
	conflict bool
}

// errJoinIntent is a start or approval refused because of its
// intent; status is the HTTP code the caller gets.
type errJoinIntent struct {
	status int
	msg    string
}

func (r *onboardRegistry) createIntent(creator, profile string) *joinIntent {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	now := time.Now()
	in := &joinIntent{
		id:      randomString(joinIntentIDBytes),
		creator: creator,
		profile: profile,
		created: now,
		seen:    now,
	}
	r.intents[in.id] = in
	return in
}

func (r *onboardRegistry) intentByID(id string) *joinIntent {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	return r.intents[id]
}

// touchIntent records a status poll, which keeps an unused intent
// alive. A lapsed intent stays lapsed.
func (r *onboardRegistry) touchIntent(in *joinIntent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if in.stateLocked(now) != joinIntentExpired {
		in.seen = now
	}
}

// bindIntentLocked attaches s to the intent named id and applies the
// intent's profile and the CLI's --hostname, lowercased, to it. A
// second start cancels the intent and the session it had bound, so
// neither device joins.
func (r *onboardRegistry) bindIntentLocked(id string, s *onboardSession) *errJoinIntent {
	if s.wholeMachine {
		return &errJoinIntent{http.StatusBadRequest, "a join from an agent prompt runs per process; drop --whole-machine"}
	}
	in := r.intents[id]
	if in == nil || (in.session == nil && in.stateLocked(time.Now()) == joinIntentExpired) {
		return &errJoinIntent{http.StatusNotFound, "unknown or expired join intent; ask for a new prompt on the dashboard"}
	}
	if in.rejected || in.conflict {
		return &errJoinIntent{http.StatusConflict, "this join intent was cancelled; ask for a new prompt on the dashboard"}
	}
	if in.session != nil {
		// Once the operator approved the first device, that join
		// stands; only a pending one is cancelled with the intent.
		if in.session.approved {
			return &errJoinIntent{http.StatusConflict, "this join intent was already used; ask for a new prompt on the dashboard"}
		}
		in.conflict = true
		in.session.err = "a second device used this join intent; ask for a new prompt on the dashboard"
		return &errJoinIntent{http.StatusConflict, "this join intent was already used by another device; both joins are cancelled"}
	}
	name := strings.ToLower(s.hostname)
	if name == "" {
		return &errJoinIntent{http.StatusBadRequest, "a join from an agent prompt needs --hostname <machine>-<account>; this client may be too old for the prompt"}
	}
	if !validDeviceName(name) {
		return &errJoinIntent{http.StatusBadRequest, fmt.Sprintf("device name %q is not valid: letters, digits, '.', '_' and '-' only, at most %d characters", name, maxDeviceNameLen)}
	}
	in.session = s
	s.intent = in
	s.hostname = name
	s.profile = in.profile
	return nil
}

// dropSessionLocked forgets a session that never got going (its
// start was refused).
func (r *onboardRegistry) dropSessionLocked(s *onboardSession) {
	delete(r.byDevice, s.deviceCode)
	delete(r.byUser, s.userCode)
}

func (r *onboardRegistry) gcIntentsLocked(now time.Time) {
	for id, in := range r.intents {
		if now.Sub(in.seen) > joinIntentRetention {
			delete(r.intents, id)
		}
	}
}

// stateLocked derives what the Add device window shows.
func (in *joinIntent) stateLocked(now time.Time) joinIntentState {
	s := in.session
	switch {
	case in.rejected:
		return joinIntentRejected
	case in.conflict:
		return joinIntentConflict
	case s == nil && (now.Sub(in.seen) > joinIntentIdle || now.Sub(in.created) > joinIntentMaxAge):
		return joinIntentExpired
	case s == nil:
		return joinIntentWaiting
	case s.err != "":
		return joinIntentFailed
	case s.delivered:
		return joinIntentJoined
	case now.Sub(s.created) > onboardSessionTTL:
		return joinIntentExpired
	case s.approved:
		return joinIntentApproved
	default:
		return joinIntentPending
	}
}

// deviceRef is a registered device as the Add device window shows it.
type deviceRef struct {
	Name    string `json:"name"`
	Profile string `json:"profile"`
}

type joinIntentDevice struct {
	Name     string `json:"name"`
	UserCode string `json:"user_code"`
}

type joinIntentStatus struct {
	ID        string            `json:"id"`
	State     joinIntentState   `json:"state"`
	Profile   string            `json:"profile"`
	ExpiresAt int64             `json:"expires_at"`
	Device    *joinIntentDevice `json:"device,omitempty"`
	// Replaces is the device this join would take over on approval.
	Replaces *deviceRef `json:"replaces,omitempty"`
	Error    string     `json:"error,omitempty"`
}

func (w *webMux) joinIntentStatus(in *joinIntent) joinIntentStatus {
	now := time.Now()
	w.onboard.mu.Lock()
	st := joinIntentStatus{
		ID:        in.id,
		State:     in.stateLocked(now),
		Profile:   in.profile,
		ExpiresAt: min(in.seen.Add(joinIntentIdle).Unix(), in.created.Add(joinIntentMaxAge).Unix()),
	}
	var name string
	if s := in.session; s != nil {
		name = s.hostname
		st.Device = &joinIntentDevice{Name: name, UserCode: s.userCode}
		st.ExpiresAt = s.created.Add(onboardSessionTTL).Unix()
		st.Error = s.err
	}
	w.onboard.mu.Unlock()
	if st.Device == nil {
		return st
	}

	if ip := w.onboard.IPForHostname(in.profile, in.profile, name); ip != "" {
		st.Replaces = &deviceRef{Name: name, Profile: in.profile}
	}
	return st
}

// intentForCaller returns the intent named in the request if the
// caller may see it: its creator, or an admin.
func (w *webMux) intentForCaller(rw http.ResponseWriter, r *http.Request, id string) *joinIntent {
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)
		return nil
	}
	in := w.onboard.intentByID(id)
	if in == nil || (!v.admin && in.creator != v.username) {
		http.Error(rw, "unknown or expired join intent", http.StatusNotFound)
		return nil
	}
	return in
}

type joinIntentRequest struct {
	ID      string `json:"id"`
	Profile string `json:"profile"`
	// IfUnused limits a reject to an intent no device has used yet, as
	// when the window replaces its prompt: a join the agent already
	// started stays for the operator to decide.
	IfUnused bool `json:"if_unused"`
}

func decodeJoinIntentRequest(r *http.Request) (joinIntentRequest, error) {
	var body joinIntentRequest
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxJoinIntentBody))
	if err != nil {
		return body, fmt.Errorf("read body: %w", err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return body, fmt.Errorf("body must be JSON: %w", err)
	}
	body.Profile = strings.TrimSpace(body.Profile)
	return body, nil
}

// apiOnboardIntentCreate: POST /api/onboard/intent {profile}.
// A member may create one only for a profile of their own.
func (w *webMux) apiOnboardIntentCreate(rw http.ResponseWriter, r *http.Request) {
	v, err := w.viewerFor(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)
		return
	}
	body, err := decodeJoinIntentRequest(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	profiles := orderedProfileNames(w.g.cfg.Load().Policy)
	// A policy with no profiles has nothing to choose from; the join
	// then gets whatever approve assigns, as with the Commands tab.
	profile := resolveProfileFromList(profiles, body.Profile)
	if len(profiles) > 0 && body.Profile != "" && !slices.Contains(profiles, body.Profile) {
		http.Error(rw, fmt.Sprintf("unknown profile %q", body.Profile), http.StatusBadRequest)
		return
	}
	if !v.ownsProfile(profile) {
		http.Error(rw, "choose one of your profiles for this device", http.StatusForbidden)
		return
	}
	in := w.onboard.createIntent(v.username, profile)
	st := w.joinIntentStatus(in)
	writeJSON(rw, map[string]any{
		"id":             in.id,
		"profile":        profile,
		"expires_at":     st.ExpiresAt,
		"ca_fingerprint": w.caFingerprint(),
	})
}

// apiOnboardIntentStatus: GET /api/onboard/intent/status?id=… — what
// the Add device window polls while the agent joins. Each poll keeps
// an unused intent alive.
func (w *webMux) apiOnboardIntentStatus(rw http.ResponseWriter, r *http.Request) {
	in := w.intentForCaller(rw, r, r.URL.Query().Get("id"))
	if in == nil {
		return
	}
	w.onboard.touchIntent(in)
	writeJSON(rw, w.joinIntentStatus(in))
}

// apiOnboardIntentReject: POST /api/onboard/intent/reject {id, if_unused?}.
// The waiting CLI gets an error on its next poll; nothing joins.
func (w *webMux) apiOnboardIntentReject(rw http.ResponseWriter, r *http.Request) {
	body, err := decodeJoinIntentRequest(r)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	in := w.intentForCaller(rw, r, body.ID)
	if in == nil {
		return
	}
	w.onboard.mu.Lock()
	if body.IfUnused && in.session != nil {
		w.onboard.mu.Unlock()
		http.Error(rw, "a device already used this prompt", http.StatusConflict)
		return
	}
	if s := in.session; s != nil && s.approved {
		w.onboard.mu.Unlock()
		http.Error(rw, "already approved; remove the device from the Devices page instead", http.StatusConflict)
		return
	}
	in.rejected = true
	if in.session != nil {
		in.session.err = "rejected on the dashboard"
	}
	w.onboard.mu.Unlock()
	writeJSON(rw, w.joinIntentStatus(in))
}

// checkIntentApprovalLocked holds an approval of an intent join to what
// the operator chose for it: its profile, and no takeover of an existing
// device without replace. Sessions without an intent pass. Caller holds
// the registry lock.
func checkIntentApprovalLocked(s *onboardSession, profile string, replaces, replace bool) *errJoinIntent {
	in := s.intent
	if in == nil {
		return nil
	}
	if in.rejected || in.conflict {
		return &errJoinIntent{http.StatusConflict, "this join was cancelled"}
	}
	if profile != in.profile {
		return &errJoinIntent{http.StatusForbidden, fmt.Sprintf("this device joins profile %q, chosen when the prompt was made", in.profile)}
	}
	if replaces && !replace {
		return &errJoinIntent{http.StatusConflict, fmt.Sprintf("approving would replace the existing device %s; confirm the replacement", s.hostname)}
	}
	return nil
}
