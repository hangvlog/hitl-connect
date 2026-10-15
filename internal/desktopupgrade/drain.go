package desktopupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// A v3 GUI can own the provider in-process. Before terminating an eligible
// panel, use its existing private local capability to stop admission and wait
// for sessions. Never infer safety from a zero/unknown process connection count.
func drainPanel(args []string) error {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	base = filepath.Join(base, "hitl-connect")
	for i := 2; i+1 < len(args); i++ {
		if args[i] == "--dir" {
			base = args[i+1]
		}
	}
	data, err := os.ReadFile(filepath.Join(base, "gui-session.json"))
	if err != nil {
		return errors.New("Panel state unavailable; close it after active work completes")
	}
	var d struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &d) != nil {
		return errors.New("Invalid panel state")
	}
	u, err := url.Parse(d.URL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(d.Token) != 64 {
		return errors.New("Invalid panel endpoint")
	}
	client := &http.Client{Timeout: 65 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(action string, post bool) (*http.Response, error) {
		method := "GET"
		var body io.Reader
		if post {
			method = "POST"
			body = bytes.NewBufferString("{}")
		}
		req, err := http.NewRequest(method, d.URL+"/api/"+action, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+d.Token)
		req.Header.Set("Origin", d.URL)
		req.Header.Set("Content-Type", "application/json")
		return client.Do(req)
	}
	res, err := call("state", false)
	if err != nil {
		return errors.New("Cannot verify panel state; update deferred")
	}
	var state struct {
		Running bool `json:"running"`
		Managed bool `json:"managed"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&state)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 {
		return errors.New("Cannot verify panel state; update deferred")
	}
	// This panel only proxies a separately installed service, whose binary and
	// lifecycle are outside a desktop-only update.
	if !state.Running || state.Managed {
		return nil
	}
	res, err = call("drain", true)
	if err != nil {
		return errors.New("Cannot drain panel; update deferred")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("Active sessions or older client: update deferred; finish work before closing the panel")
	}
	return nil
}
