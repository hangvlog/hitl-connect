package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPPublicationConfiguration(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "panel")
	profile := filepath.Join(base, "public-host")
	if err := initialize("example-device", profile, "https://relay.example.invalid/hitl/device-tunnel"); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(profile, "config.json")
	before, _ := os.ReadFile(config)
	s, err := saveHTTPPublication(config, "", "127.0.0.1:8000", true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "8000" || len(s.Token) != 64 {
		t.Fatal("invalid defaults")
	}
	c, err := load(config)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := httpServiceURL(c, s.Name)
	if u != "https://relay.example.invalid/hitl/services/example-device/8000/" {
		t.Fatal(u)
	}
	changed, err := saveHTTPPublication(config, s.Name, "127.0.0.1:9000", true)
	if err != nil || changed.Token != s.Token {
		t.Fatal("port update changed credential", err)
	}
	disabled, err := saveHTTPPublication(config, s.Name, "", false)
	if err != nil || disabled.Enabled {
		t.Fatal(err)
	}
	if _, err = saveHTTPPublication(config, "unsafe", "10.0.0.1:8000", true); err == nil {
		t.Fatal("non-loopback accepted")
	}
	after, _ := os.ReadFile(config)
	if string(before) != string(after) {
		t.Fatal("identity configuration changed")
	}
	output := filepath.Join(root, "credentials.private.json")
	if err = os.WriteFile(output, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = httpCommand(context.Background(), []string{"publish", "--config", config, "--port", "8001", "--output", output}); err == nil {
		t.Fatal("overwrote existing output")
	}
	got, _ := os.ReadFile(output)
	if string(got) != "existing" {
		t.Fatal("changed existing output")
	}
	g := newGUI(base, "fixture")
	g.origin = "http://127.0.0.1:12345"
	call := func(action, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", g.origin+"/api/"+action, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+g.token)
		r.Header.Set("Origin", g.origin)
		w := httptest.NewRecorder()
		g.handler().ServeHTTP(w, r)
		return w
	}
	w := call("http-publish", `{"httpPort":8000,"serviceName":"model-api"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), s.Token) {
		t.Fatal("list leaked token")
	}
	w = call("http-credentials", `{"serviceName":"model-api"}`)
	var creds map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &creds) != nil || len(creds["token"]) != 64 {
		t.Fatal("credentials not available locally")
	}
	w = call("http-disable", `{"serviceName":"model-api"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}
