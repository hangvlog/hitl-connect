package desktopupgrade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnlyExactCurrentUserDesktopPanelMayClose(t *testing.T) {
	path := `C:\self\HITL Connect\HITL-Connect.exe`
	for _, args := range [][]string{{path}, {path, "gui", "--dir", `C:\Users\owner\profile`, "--no-open"}} {
		if !eligiblePanel(path, path, "owner", "owner", 1, 1, args) {
			t.Fatal("panel rejected")
		}
	}
	for _, args := range [][]string{nil, {path, "host-service"}, {path, "ssh-account-worker"}, {path, "install-host"}, {path, "agent", "allow"}, {path, "host"}, {path, "gui", "--unknown"}, {path, "gui", "--dir"}} {
		if eligiblePanel(path, path, "owner", "owner", 1, 1, args) {
			t.Fatalf("non-panel accepted: %v", args)
		}
	}
	for _, c := range []struct {
		image, sid string
		session    uint32
	}{
		{`C:\other\HITL-Connect.exe`, "owner", 1}, {path, "other", 1}, {path, "owner", 0}, {path, "owner", 2},
	} {
		if eligiblePanel(c.image, path, c.sid, "owner", c.session, 1, []string{path}) {
			t.Fatal("process boundary bypass")
		}
	}
}

func TestDesktopUpgradeDoesNotDrainIndependentManagedService(t *testing.T) {
	drained := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/state" {
			w.Write([]byte(`{"running":true,"managed":true}`))
			return
		}
		drained = true
		w.WriteHeader(409)
	}))
	defer server.Close()
	dir := t.TempDir()
	b, _ := json.Marshal(map[string]string{"url": server.URL, "token": strings.Repeat("a", 64)})
	if err := os.WriteFile(filepath.Join(dir, "gui-session.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := drainPanel([]string{"app", "gui", "--dir", dir}); err != nil {
		t.Fatal(err)
	}
	if drained {
		t.Fatal("desktop update drained independent background service")
	}
}
