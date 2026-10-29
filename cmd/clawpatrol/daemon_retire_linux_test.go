//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// joinFilesForTest points the join files at a fresh HOME and writes a
// WireGuard-mode join whose wg.conf carries addr.
func joinFilesForTest(t *testing.T, addr string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	if err := os.MkdirAll(defaultClawpatrolDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(defaultClawpatrolDir(), "mode"), []byte("wireguard\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rewriteWGConfForTest(t, addr)
}

func rewriteWGConfForTest(t *testing.T, addr string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(defaultRunConf()), 0o700); err != nil {
		t.Fatal(err)
	}
	conf := "[Interface]\nAddress = " + addr + "/32\n"
	if err := os.WriteFile(defaultRunConf(), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

// serveDaemonForTest starts a daemon's accept loop on a real socket. The
// socket lives under os.TempDir rather than t.TempDir, whose long paths
// can exceed sun_path.
func serveDaemonForTest(t *testing.T, sessions int32) (d *daemon, served chan struct{}, exits chan int) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cpd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	lf, err := os.OpenFile(filepath.Join(dir, "spawn.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lf.Close(); _ = ln.Close() })

	exits = make(chan int, 1)
	prevExit := daemonExit
	daemonExit = func(code int) { exits <- code }
	t.Cleanup(func() { daemonExit = prevExit })

	d = &daemon{
		sockPath: sockPath,
		lockFile: lf,
		listener: ln,
		identity: daemonIdentity(),
		rebindCh: make(chan struct{}),
	}
	d.activeConns.Store(sessions)
	served = make(chan struct{})
	go func() {
		d.serve()
		close(served)
	}()
	return d, served, exits
}

func TestDaemonRetiresAfterRejoin(t *testing.T) {
	joinFilesForTest(t, "10.55.0.2")
	// One `clawpatrol run` is attached: it keeps the old tunnel, and the
	// daemon must outlive the retirement for it.
	d, served, exits := serveDaemonForTest(t, 1)

	c, ok := daemonDialAndHello(d.sockPath)
	if !ok {
		t.Fatal("hello failed before any rejoin")
	}
	_ = c.Close()

	rewriteWGConfForTest(t, "10.55.0.3")

	if c, ok := daemonDialAndHello(d.sockPath); ok {
		_ = c.Close()
		t.Fatal("daemon still served a session after the join files changed")
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop kept running after retiring")
	}
	if _, err := os.Stat(d.sockPath); !os.IsNotExist(err) {
		t.Fatalf("control socket still present after retiring (stat err %v); the next run would not spawn a fresh daemon", err)
	}
	if !d.isRetired() {
		t.Fatal("daemon not marked retired")
	}
	select {
	case code := <-exits:
		t.Fatalf("daemon exited (code %d) under an attached session", code)
	default:
	}
}

func TestDaemonRetiresAndExitsWithNoSessions(t *testing.T) {
	joinFilesForTest(t, "10.55.0.2")
	d, _, exits := serveDaemonForTest(t, 0)

	rewriteWGConfForTest(t, "10.55.0.3")
	if c, ok := daemonDialAndHello(d.sockPath); ok {
		_ = c.Close()
		t.Fatal("daemon still served a session after the join files changed")
	}
	select {
	case code := <-exits:
		if code != 0 {
			t.Fatalf("exit code %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retired daemon with no sessions did not exit")
	}
}

func TestDaemonIdentityTracksJoinFiles(t *testing.T) {
	joinFilesForTest(t, "10.55.0.2")
	before := daemonIdentity()
	if again := daemonIdentity(); again != before {
		t.Fatal("identity differs with no change to the join files")
	}
	if err := os.WriteFile(filepath.Join(defaultClawpatrolDir(), "api-token"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if daemonIdentity() == before {
		t.Fatal("a new api-token left the identity unchanged")
	}
}
