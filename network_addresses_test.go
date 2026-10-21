package main

import (
	"context"
	"github.com/coder/websocket"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestLocalAddressesAreBoundedAndUnicast(t *testing.T) {
	got := normalizedLocalAddresses([]string{"127.0.0.1/8", "::1/128", "fe80::1/64", "224.0.0.1/4", "0.0.0.0/0", "192.168.1.2/24", "::ffff:192.168.1.2/120", "2001:db8::1/64", "bad"})
	if !reflect.DeepEqual(got, []string{"192.168.1.2", "2001:db8::1"}) {
		t.Fatalf("unexpected addresses: %v", got)
	}
}
func TestOpenRelayReportsLocalAddresses(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-Connect-Local-Ips")
		ws, err := websocket.Accept(w, r, nil)
		if err == nil {
			ws.CloseNow()
		}
	}))
	defer server.Close()
	ws, err := openRelay(context.Background(), &Config{Token: strings.Repeat("a", 64)}, "ws"+strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatal(err)
	}
	ws.CloseNow()
	if got := <-received; got != strings.Join(localAddresses(), ",") {
		t.Fatal("missing local address report")
	}
}
