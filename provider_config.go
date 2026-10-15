package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Save only a local deployment setting. Identity and authorization creation
// remain in the existing provider and native installation flows.
func prepareProviderRelay(base, relay string) error {
	profile := filepath.Join(base, "public-host")
	config := filepath.Join(profile, "config.json")
	relay = strings.TrimSpace(relay)
	if c, err := load(config); err == nil {
		if relay != "" && strings.TrimRight(relay, "/") != strings.TrimRight(c.Relay, "/") {
			return errors.New("RELAY_CHANGE_REQUIRES_NEW_PROFILE: existing identity and trust were preserved")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if relay == "" {
		_, err := localProviderRelay(profile)
		return err
	}
	if _, err := relayBaseURL(&Config{Relay: relay}); err != nil {
		return err
	}
	if err := os.MkdirAll(profile, 0700); err != nil {
		return err
	}
	return privateJSON(filepath.Join(profile, "relay.local.json"), localRelaySettings{Relay: relay})
}

type localRelaySettings struct {
	Relay string `json:"relay"`
}

func localProviderRelay(profile string) (string, error) {
	var settings localRelaySettings
	if err := readJSON(filepath.Join(profile, "relay.local.json"), &settings); err != nil {
		return "", errors.New("RELAY_REQUIRED: configure your relay locally or supply --relay")
	}
	if _, err := relayBaseURL(&Config{Relay: settings.Relay}); err != nil {
		return "", err
	}
	return settings.Relay, nil
}
