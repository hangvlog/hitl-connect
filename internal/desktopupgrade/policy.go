// Package desktopupgrade prepares a per-user client directory for replacement.
// It never changes a service, profile, authorization or startup registration.
package desktopupgrade

import "strings"

// Only the panel process may be closed. Active commands, workers, installers
// and provider processes require their owner to finish them first.
func panelCommand(args []string) bool {
	if len(args) == 1 {
		return true
	}
	if len(args) < 2 || args[1] != "gui" {
		return false
	}
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--no-open":
		case "--dir", "--bind":
			i++
			if i == len(args) || args[i] == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func eligiblePanel(image, target, sid, owner string, session, currentSession uint32, args []string) bool {
	return strings.EqualFold(image, target) && sid != "" && sid == owner &&
		session != 0 && session == currentSession && panelCommand(args)
}
