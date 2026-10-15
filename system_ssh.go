package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// An unreadable/stale descriptor is not evidence that the provider is stopped.
// Only SCM plus the profile lock can establish that no provider needs draining.
func quiesceSystemSSHProvider(ctx context.Context, root string, interrupt, serviceActive bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := agentSession(root)
	if err == nil {
		var state guiState
		err = agentCall(ctx, d, "state", nil, &state)
	}
	if err != nil {
		if interrupt {
			return nil
		}
		release, acquired, lockErr := tryProfileLock(root, ".panel.lock")
		if lockErr != nil {
			return lockErr
		}
		if acquired {
			defer release()
		}
		if serviceActive || !acquired {
			return errors.New("UPDATE_DRAIN_UNAVAILABLE: provider state is unknown; existing sessions were not interrupted")
		}
		return nil
	}
	var reply struct {
		OK bool `json:"ok"`
	}
	if !interrupt {
		if err = agentCall(ctx, d, "drain", &guiRequest{}, &reply); err != nil {
			return err
		}
		if !reply.OK {
			return errors.New("UPDATE_DRAIN_UNCONFIRMED")
		}
	}
	reply.OK = false
	if err = agentCall(ctx, d, "quit", &guiRequest{}, &reply); err != nil {
		return err
	}
	if !reply.OK {
		return errors.New("UPDATE_QUIT_UNCONFIRMED")
	}
	return nil
}

func systemSSHPolicy(profile string) (hostAuthorization, bool) {
	a, err := readHostAuthorization(profile)
	return a, err == nil && a.Version == 3 && a.Engine == "openssh"
}

// Generate only the current grant's account-bound keys. Remote input cannot
// introduce authorized_keys options, another account or an arbitrary path.
func systemSSHKeys(profile string, policy hostAuthorization, candidate *sshAccess) ([]byte, error) {
	var grant sshGrant
	if err := readJSON(filepath.Join(profile, "ssh-grant.json"), &grant); err != nil {
		return nil, err
	}
	if grant.User != policy.User {
		return nil, errors.New("HOST_SCOPE_FIXED")
	}
	if grant.Disabled {
		if candidate != nil {
			return nil, errors.New("CONNECTION_CODE_DISABLED")
		}
		return []byte("# HITL Connect: connection code disabled\n"), nil
	}
	entries := listSSHAccess(profile)
	if candidate != nil {
		entries = append(entries, *candidate)
	}
	keys := map[string]bool{}
	candidateAccepted := candidate == nil
	var data strings.Builder
	data.WriteString("# HITL Connect: current account and connection grant only\n")
	for _, entry := range entries {
		path, err := accessPath(profile, entry.ID)
		if err != nil {
			return nil, err
		}
		var a sshAccess
		if err = readJSON(path, &a); err != nil {
			return nil, err
		}
		isCandidate := candidate != nil && a.ID == candidate.ID
		if isCandidate && a.Fingerprint != candidate.Fingerprint {
			return nil, errors.New("PUBLIC_KEY_MISMATCH")
		}
		if !accessUsesGrant(a, grant) || (a.Status != "approved" && !(isCandidate && a.Status == "configuring")) {
			continue
		}
		if a.Status == "approved" && a.User != policy.User {
			return nil, errors.New("HOST_SCOPE_FIXED")
		}
		key, err := plainSSHKey([]byte(a.PublicKey))
		if err != nil || ssh.FingerprintSHA256(key) != a.Fingerprint {
			return nil, errors.New("PUBLIC_KEY_MISMATCH")
		}
		public := string(ssh.MarshalAuthorizedKey(key))
		if isCandidate {
			candidateAccepted = true
		}
		if !keys[public] {
			data.WriteString("restrict " + public)
			keys[public] = true
		}
	}
	if !candidateAccepted {
		return nil, errors.New("ACCESS_REQUEST_CLOSED")
	}
	return []byte(data.String()), nil
}
