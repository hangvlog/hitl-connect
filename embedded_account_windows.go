package main

import "strings"

// Windows accepts local username and COMPUTER\username for the same account.
// Authenticate the immutable SID, while retaining the locally selected display
// name in grants/audit. Never normalize strings into a different local account.
func embeddedLoginUser(policy hostAuthorization, user string) bool {
	if len(user) == 0 || len(user) > 128 || strings.TrimSpace(user) != user {
		return false
	}
	_, sid, err := nativeLocalAccount(user)
	return err == nil && sid == policy.SID
}
