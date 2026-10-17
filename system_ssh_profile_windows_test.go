package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemSSHServiceProfileIgnoresUserLocator(t *testing.T) {
	base := filepath.Join(t.TempDir(), "unavailable-user-profile")
	owner := "S-1-5-21-111-222-333-1001"
	want, _, err := managedLocation(base, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, locator := range []string{"", `{"profile":"C:\\untrusted-location"}`} {
		if locator != "" {
			if err := os.MkdirAll(base, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "managed-host.json"), []byte(locator), 0600); err != nil {
				t.Fatal(err)
			}
		}
		got, sid, err := systemSSHProfile(base, "S-1-5-18", owner, true)
		if err != nil || got != want || sid != owner {
			t.Fatalf("root=%q sid=%q err=%v", got, sid, err)
		}
	}
	for _, tc := range []struct {
		caller  string
		service bool
	}{{owner, false}, {owner, true}, {"S-1-5-18", false}} {
		if _, _, err := systemSSHProfile(base, tc.caller, owner, tc.service); err == nil {
			t.Fatal("accepted owner override outside SYSTEM service", tc)
		}
	}
}

func TestSystemSSHInteractiveProfileRequiresExistingLocator(t *testing.T) {
	base := t.TempDir()
	owner := "S-1-5-21-111-222-333-1001"
	if _, _, err := systemSSHProfile(base, owner, "", false); err == nil {
		t.Fatal("accepted absent interactive locator")
	}
	want, _, err := managedLocation(base, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateJSON(filepath.Join(base, "managed-host.json"), managedLocator{want}); err != nil {
		t.Fatal(err)
	}
	if got, sid, err := systemSSHProfile(base, owner, "", false); err != nil || got != want || sid != owner {
		t.Fatal(got, sid, err)
	}
	if err := privateJSON(filepath.Join(base, "managed-host.json"), managedLocator{filepath.Join(t.TempDir(), "other")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := systemSSHProfile(base, owner, "", false); err == nil {
		t.Fatal("accepted unrelated interactive profile")
	}
}
