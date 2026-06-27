package governance

import (
	"context"
	"testing"
	"time"

	"github.com/Privasys/chat-service/internal/mgmt"
	"github.com/Privasys/chat-service/internal/store"
)

type fakeResolver struct {
	apps map[string]*mgmt.App
}

func (f fakeResolver) ResolveEnclaveApp(_ context.Context, ref string) (*mgmt.App, error) {
	if a, ok := f.apps[ref]; ok {
		return a, nil
	}
	return &mgmt.App{ID: ref, IsEnclave: false}, nil
}

func TestAdmits(t *testing.T) {
	cases := []struct {
		policy, kind string
		want         bool
	}{
		{PolicyLocked, "enclave", false},
		{PolicyLocked, "external", false},
		{PolicyEnclaveOnly, "enclave", true},
		{PolicyEnclaveOnly, "external", false},
		{PolicyOpen, "enclave", true},
		{PolicyOpen, "external", true},
		{"", "enclave", false}, // unknown → locked
	}
	for _, c := range cases {
		if got := Admits(c.policy, c.kind); got != c.want {
			t.Errorf("Admits(%q,%q)=%v want %v", c.policy, c.kind, got, c.want)
		}
	}
}

func TestResolve(t *testing.T) {
	now := time.Now()
	res := fakeResolver{apps: map[string]*mgmt.App{
		"good-app": {ID: "good-app", IsEnclave: true, Endpoint: "https://good.apps.privasys.org", ExpectedDigest: "abc"},
	}}
	tools := []store.UserTool{
		{Name: "good", Kind: "enclave", Ref: "good-app", Enabled: true},
		{Name: "notenclave", Kind: "enclave", Ref: "missing-app", Enabled: true},
		{Name: "ext", Kind: "external", Ref: "https://ext.example.com", Enabled: true, AcknowledgedAt: &now},
		{Name: "extnoack", Kind: "external", Ref: "https://ext2.example.com", Enabled: true},
		{Name: "disabled", Kind: "enclave", Ref: "good-app", Enabled: false},
	}

	t.Run("locked yields nothing", func(t *testing.T) {
		got := Resolve(context.Background(), res, &mgmt.Instance{ToolPolicy: PolicyLocked}, tools)
		if len(got) != 0 {
			t.Fatalf("want 0 tools, got %d", len(got))
		}
	})

	t.Run("enclave_only admits only verifiable enclave tools", func(t *testing.T) {
		got := Resolve(context.Background(), res, &mgmt.Instance{ToolPolicy: PolicyEnclaveOnly}, tools)
		if len(got) != 1 || got[0].Name != "good" {
			t.Fatalf("want [good], got %+v", got)
		}
		if !got[0].Verified || got[0].BaseURL != "https://good.apps.privasys.org" || got[0].ExpectedDigest != "abc" {
			t.Fatalf("enclave tool not resolved correctly: %+v", got[0])
		}
	})

	t.Run("open admits enclave + acknowledged external", func(t *testing.T) {
		got := Resolve(context.Background(), res, &mgmt.Instance{ToolPolicy: PolicyOpen}, tools)
		names := map[string]bool{}
		for _, g := range got {
			names[g.Name] = true
		}
		if !names["good"] || !names["ext"] {
			t.Fatalf("want good+ext, got %+v", got)
		}
		if names["extnoack"] {
			t.Fatalf("unacknowledged external must be excluded")
		}
		for _, g := range got {
			if g.Name == "ext" && g.Verified {
				t.Fatalf("external tool must be verified=false")
			}
		}
	})
}
