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
// its own profile), so an intent join is named <machine>-<account>
// unless the operator typed a name, and the status reports the other
// devices named after the same machine.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
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
	maxDeviceNameLen    = 63
	maxJoinIntentBody   = 4 << 10
)

// deviceNamePattern is what an intent accepts for a device name and
// for the OS hostname and account it is built from.
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
	id         string
	creator    string // dashboard principal that created it
	profile    string
	deviceName string // operator-typed; empty = <machine>-<account>
	created    time.Time
	session    *onboardSession
	rejected   bool
	conflict   bool
}

// errJoinIntent is a start or approval refused because of its
// intent; status is the HTTP code the caller gets.
type errJoinIntent struct {
	status int
	msg    string
}

func (r *onboardRegistry) createIntent(creator, profile, deviceName string) *joinIntent {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	in := &joinIntent{
		id:         randomString(joinIntentIDBytes),
		creator:    creator,
		profile:    profile,
		deviceName: deviceName,
		created:    time.Now(),
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

// bindIntentLocked attaches s to the intent named id and applies the
// intent's profile and device name to it. A second start cancels the
// intent and the session it had bound, so neither device joins.
func (r *onboardRegistry) bindIntentLocked(id string, s *onboardSession) *errJoinIntent {
	if s.wholeMachine {
		return &errJoinIntent{http.StatusBadRequest, "a join from an agent prompt runs per process; drop --whole-machine"}
	}
	in := r.intents[id]
	if in == nil || time.Since(in.created) > onboardSessionTTL {
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
	name := in.deviceName
	if name == "" {
		if s.osHostname == "" {
			return &errJoinIntent{http.StatusBadRequest, "this machine's hostname cannot name a device; make a new prompt with a device name"}
		}
		name = s.osHostname
		if s.osUser != "" {
			name += "-" + s.osUser
		}
	}
	if !validDeviceName(name) {
		return &errJoinIntent{http.StatusBadRequest, fmt.Sprintf("device name %q is too long or not valid; make a new prompt with a device name", name)}
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
		if now.Sub(in.created) > joinIntentRetention {
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
	case s == nil && now.Sub(in.created) > onboardSessionTTL:
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

// deviceRef is a registered device as the Add device window lists it.
// ByName marks a device that predates the recorded OS hostname and is
// only matched by its name, so it may be on another machine.
type deviceRef struct {
	Name    string `json:"name"`
	Profile string `json:"profile"`
	ByName  bool   `json:"by_name,omitempty"`
}

// DevicesOnMachine lists the devices that joined from machine: those
// whose recorded OS hostname is machine and, for devices without one,
// those named machine or machine-<one label>, as shared hosts name them.
func (r *onboardRegistry) DevicesOnMachine(machine string) []deviceRef {
	if machine == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []deviceRef
	for ip, name := range r.hostnameByIP {
		if host, ok := r.osHostByIP[ip]; ok {
			if host == machine {
				out = append(out, deviceRef{Name: name, Profile: r.profileByIP[ip]})
			}
			continue
		}
		if namedAfterMachine(name, machine) {
			out = append(out, deviceRef{Name: name, Profile: r.profileByIP[ip], ByName: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func namedAfterMachine(name, machine string) bool {
	if name == machine {
		return true
	}
	rest, ok := strings.CutPrefix(name, machine+"-")
	return ok && rest != "" && !strings.Contains(rest, "-")
}

type joinIntentDevice struct {
	Name       string `json:"name"`
	OSHostname string `json:"os_hostname"`
	OSUser     string `json:"os_user"`
	OS         string `json:"os"`
	UserCode   string `json:"user_code"`
}

type joinIntentStatus struct {
	ID        string            `json:"id"`
	State     joinIntentState   `json:"state"`
	Profile   string            `json:"profile"`
	ExpiresAt int64             `json:"expires_at"`
	Device    *joinIntentDevice `json:"device,omitempty"`
	// Replaces is the device this join would take over on approval.
	Replaces *deviceRef `json:"replaces,omitempty"`
	// OnMachine lists the other devices named after the same machine.
	OnMachine []deviceRef `json:"on_machine,omitempty"`
	Warnings  []string    `json:"warnings,omitempty"`
	Error     string      `json:"error,omitempty"`
}

func (w *webMux) joinIntentStatus(in *joinIntent) joinIntentStatus {
	now := time.Now()
	w.onboard.mu.Lock()
	st := joinIntentStatus{
		ID:        in.id,
		State:     in.stateLocked(now),
		Profile:   in.profile,
		ExpiresAt: in.created.Add(onboardSessionTTL).Unix(),
	}
	var name, machine, osUser string
	if s := in.session; s != nil {
		name, machine, osUser = s.hostname, s.osHostname, s.osUser
		st.Device = &joinIntentDevice{Name: name, OSHostname: machine, OSUser: osUser, OS: s.os, UserCode: s.userCode}
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
	for _, d := range w.onboard.DevicesOnMachine(machine) {
		if d.Name == name && d.Profile == in.profile {
			continue
		}
		st.OnMachine = append(st.OnMachine, d)
		// One account per profile is the usual shape of a shared host:
		// another device of this profile on the machine suggests the
		// agent runs in the wrong OS account. A match by name alone is
		// too weak to warn about.
		if !d.ByName && d.Profile == in.profile && d.Name != name {
			st.Warnings = append(st.Warnings, fmt.Sprintf(
				"profile %s already has %s on this machine; this join comes from OS account %q",
				in.profile, d.Name, osUser))
		}
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
	ID         string `json:"id"`
	Profile    string `json:"profile"`
	DeviceName string `json:"device_name"`
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
	body.DeviceName = strings.TrimSpace(body.DeviceName)
	return body, nil
}

// apiOnboardIntentCreate: POST /api/onboard/intent {profile, device_name?}.
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
	if body.DeviceName != "" && !validDeviceName(body.DeviceName) {
		http.Error(rw, "device name: letters, digits, '.', '_' and '-' only, at most 63 characters", http.StatusBadRequest)
		return
	}
	in := w.onboard.createIntent(v.username, profile, body.DeviceName)
	st := w.joinIntentStatus(in)
	writeJSON(rw, map[string]any{
		"id":             in.id,
		"profile":        profile,
		"device_name":    body.DeviceName,
		"expires_at":     st.ExpiresAt,
		"ca_fingerprint": w.caFingerprint(),
	})
}

// apiOnboardIntentStatus: GET /api/onboard/intent/status?id=… — what
// the Add device window polls while the agent joins.
func (w *webMux) apiOnboardIntentStatus(rw http.ResponseWriter, r *http.Request) {
	in := w.intentForCaller(rw, r, r.URL.Query().Get("id"))
	if in == nil {
		return
	}
	writeJSON(rw, w.joinIntentStatus(in))
}

// apiOnboardIntentReject: POST /api/onboard/intent/reject {id}. The
// waiting CLI gets an error on its next poll; nothing joins.
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
