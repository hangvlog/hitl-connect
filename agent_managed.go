package main

import "errors"

// A missing or stale service session is not a missing desktop panel. Reuse
// the GUI's read-only SCM diagnosis without starting a replacement provider.
// A response from the service (including an installation/business rejection)
// remains authoritative and must never be replaced by an offline snapshot.
func managedAgentFailure(base, action string, cause error) *agentResult {
	var rejected *agentResponseError
	var installation *installerError
	if errors.As(cause, &rejected) || errors.As(cause, &installation) {
		return nil
	}
	managed, err := managedProfile(base)
	if err != nil {
		return &agentResult{Action: action, Code: "MANAGED_PROFILE_INVALID", Message: "Cannot read the existing managed profile locator", NextActions: []string{"Preserve the existing profile; ask the device administrator to check the managed profile locator"}}
	}
	if managed == "" {
		return nil
	}
	g := &guiSession{base: base}
	result := agentStateResult(action, g.managedOfflineState(managed))
	return &result
}
