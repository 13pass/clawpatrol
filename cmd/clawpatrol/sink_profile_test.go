package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSinkStampsAndPersistsProfile(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sink, err := NewSink(db, 8)
	if err != nil {
		t.Fatal(err)
	}
	sink.SetProfileResolver(func(peerIP string) string {
		if peerIP == "10.55.0.7" {
			return "team-a"
		}
		return ""
	})
	sink.Emit(Event{ID: "with-peer", Mode: "mitm", AgentIP: "10.55.0.7", Host: "gitlab.com", Action: "allow"})
	sink.Emit(Event{ID: "no-peer", Mode: "mitm", Host: "gitlab.com", Action: "allow"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}

	w := &webMux{g: &Gateway{db: db}}
	for id, want := range map[string]string{"with-peer": "team-a", "no-peer": ""} {
		ev, err := w.loadAction(id)
		if err != nil {
			t.Fatalf("loadAction(%s): %v", id, err)
		}
		if ev.Profile != want {
			t.Errorf("%s: profile = %q, want %q", id, ev.Profile, want)
		}
	}
	var nulls int
	if err := db.QueryRow(`SELECT COUNT(*) FROM actions WHERE profile IS NULL`).Scan(&nulls); err != nil || nulls != 1 {
		t.Fatalf("rows with NULL profile = %d (%v), want 1", nulls, err)
	}
}
