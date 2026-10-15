package main

import "strings"

func agentStateResult(action string, state guiState) agentResult {
	r := agentResult{Action: action, OK: true, Code: "STATUS", State: &state, LoginIdentity: state.LoginIdentity, NativeSSHExitCode: state.NativeSSHExitCode}
	for _, s := range state.Steps {
		if s.ID == "login" && s.Status == "passed" && state.Running && state.LoginIdentity != "" {
			r.LoginVerified, r.Code = true, "LOGIN_VERIFIED"
		}
		if s.Status == "failed" || s.Status == "attention" {
			r.OK = false
			if r.Code == "STATUS" {
				r.Code = strings.ToUpper(s.ID) + "_" + strings.ToUpper(s.Status)
			}
		}
	}
	if state.CanTrust {
		r.NextActions = append(r.NextActions, "verify-provider-fingerprint", "agent trust --fingerprint <verified-fingerprint>")
	} else if !r.LoginVerified && state.Running {
		r.NextActions = append(r.NextActions, "agent diagnose")
	}
	if state.Role == "host" {
		r.NextActions = []string{"agent invitation --output <private-file>", "Caller: agent start --role connect --key-file <private-file>", "Caller: agent status until loginVerified=true"}
	} else if state.AccessStatus == "configuring" {
		r.Code = "SSH_CONFIGURING"
		r.NextActions = []string{"agent status (automatic configuration is running; no approval needed)"}
	} else if state.AccessStatus == "pending" {
		r.Code = "WAITING_FOR_HOST_APPROVAL"
		r.NextActions = []string{"Wait for the provider to approve the displayed request; no public-key file transfer is needed"}
	}
	if state.GrantDisabled {
		r.OK = false
		r.Code = "CONNECTION_CODE_DISABLED"
		r.NextActions = []string{"agent renew --output <new-private-file>"}
	}
	if !state.Running {
		r.OK = false
		if r.Code == "STATUS" {
			r.Code = "NOT_RUNNING"
		}
		r.NextActions = []string{"agent start --wait"}
	}
	if state.Problem != nil {
		r.OK = false
		r.Code = state.Problem.Code
		r.Message = state.Problem.Message
		r.NextActions = []string{state.Problem.NextAction}
	}
	return r
}
