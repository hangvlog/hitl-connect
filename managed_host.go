package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The locator is an unprivileged routing hint. Authorization lives only in the
// protected installation; it never accepts authority from this file.
type managedLocator struct {
	Profile string `json:"profile"`
}

var servicePolicy *hostAuthorization // set only by the Windows service entry

func managedProfile(base string) (string, error) {
	var l managedLocator
	err := readJSON(filepath.Join(base, "managed-host.json"), &l)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil || l.Profile == "" || !filepath.IsAbs(l.Profile) || canonicalProfile(l.Profile) == canonicalProfile(base) {
		return "", errors.New("MANAGED_PROFILE_INVALID")
	}
	return l.Profile, nil
}
func (g *guiSession) forwardManaged(w http.ResponseWriter, r *http.Request) bool {
	if servicePolicy != nil {
		return false
	}
	base, err := managedProfile(g.base)
	if err == nil && base == "" {
		return false
	}
	if err == nil {
		var d guiDescriptor
		d, err = agentSession(base)
		if err == nil {
			var request *guiRequest
			if r.Method == http.MethodPost {
				request = &guiRequest{}
				dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
				dec.DisallowUnknownFields()
				err = dec.Decode(request)
				if err != nil {
					http.Error(w, "invalid request", http.StatusBadRequest)
					return true
				}
			}
			if err == nil {
				var result json.RawMessage
				err = agentCall(r.Context(), d, strings.TrimPrefix(r.URL.Path, "/api/"), request, &result)
				if err == nil {
					_, _ = w.Write(result)
					return true
				}
				var installation *installerError
				var rejected *agentResponseError
				if errors.As(err, &installation) || errors.As(err, &rejected) {
					w.WriteHeader(http.StatusBadRequest)
					failure := map[string]any{"error": err.Error()}
					if installation != nil {
						failure["installation"] = installation.Report
					}
					_ = json.NewEncoder(w).Encode(failure)
					return true
				}
			}
		}
	}
	// Keep the local panel readable when the service's ephemeral session is
	// absent or unreachable. Never fall through to local provider installation.
	state := g.managedOfflineState(base)
	if r.Method == http.MethodGet && r.URL.Path == "/api/state" || r.Method == http.MethodPost && r.URL.Path == "/api/diagnose" {
		_ = json.NewEncoder(w).Encode(state)
		return true
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": state.Problem.Code + ": " + state.Problem.Message, "service": state.Service, "nextAction": state.Problem.NextAction})
	return true
}

type managedServiceStatus struct {
	Code       string  `json:"code"`
	State      string  `json:"state"`
	Stage      string  `json:"stage"`
	NativeCode *uint32 `json:"nativeCode,omitempty"`
}

func (g *guiSession) managedOfflineState(base string) guiState {
	status := queryManagedService(g.base, base)
	problem := &connectionProblem{Code: status.Code, Side: "local", Message: "后台服务未响应，尚未恢复远程连接", NextAction: "点击检查连接重新读取服务状态；保留原资料，由设备管理员核对服务与终端防护记录"}
	switch status.Code {
	case "HOST_SERVICE_CONFIG_MISSING", "HOST_SERVICE_NOT_REGISTERED":
		problem.Message = "后台服务登记缺失，客户端安装成功但远程连接尚未恢复"
		problem.NextAction = "由设备管理员核对服务登记及终端防护处理记录，确认原因后按原配置恢复；不要手工创建会话 JSON"
	case "HOST_SERVICE_STOPPED":
		problem.Message = "后台服务已停止"
		problem.NextAction = "由设备管理员确认停止原因后，通过 Windows 服务管理器启动现有 HITL Connect 服务，再点击检查连接"
	case "HOST_SERVICE_ACCESS_DENIED":
		problem.Message = "当前账号无法读取后台服务状态"
		problem.NextAction = "请设备管理员读取现有服务状态；程序不会改写权限"
	case "HOST_SERVICE_RUNNING_UNAVAILABLE":
		problem.Message = "Windows 服务运行中，但本机管理接口未响应"
		problem.NextAction = "稍后点击检查连接；若持续未恢复，请设备管理员检查服务启动与防护记录"
	}
	state := guiState{Version: guiVersion, Managed: true, ManagedUnavailable: true, Service: &status, Role: "host", Problem: problem, Events: []string{}, CheckedAt: time.Now().Format(time.RFC3339), Steps: []guiStep{
		{"local", "后台服务", "failed", problem.Message},
		{"relay", "云端中继", "pending", "等待后台服务恢复"},
		{"tunnel", "SSH 通道", "pending", "尚未恢复"},
		{"login", "账号登录", "pending", "尚未验证"},
	}}
	if base != "" {
		if a, err := readHostAuthorization(filepath.Join(base, "public-host")); err == nil {
			state.AuthorizedUser, state.Privilege, state.SSHEngine, state.Address = a.User, a.Privilege, a.Engine, a.Address
			if a.Engine == "openssh" {
				state.Service = nil
				problem.Code = "SYSTEM_SSH_PROVIDER_NOT_RUNNING"
				problem.Message = "Windows OpenSSH 模式的 HITL 提供程序未运行"
				problem.NextAction = "双击 HITL Connect（系统 SSH）快捷方式并接受 Windows 授权；原连接码和账号保持不变"
				state.Steps[0].Detail = problem.Message
			}
		}
	}
	return state
}

// A local capability may operate the already authorized connection. It cannot
// ask the SYSTEM service to select another account, read an arbitrary key or
// connect to a caller-selected destination.
func validateManagedAction(policy *hostAuthorization, action string, r guiRequest) error {
	if policy == nil {
		return nil
	}
	switch action {
	case "start", "allow", "diagnose", "drain", "stop", "quit", "renew", "disable-code", "invitation":
	default:
		return errors.New("MANAGED_ACTION_NOT_ALLOWED")
	}
	if (r.Privilege != "" && r.Privilege != policy.Privilege) || (r.Role != "" && r.Role != "host") || (r.User != "" && r.User != policy.User) || (r.Target != "" && r.Target != policy.Address) || r.ConnectionKey != "" || r.KeyPath != "" || r.Listen != "" || r.ManualSSH || r.RequestID != "" || r.Fingerprint != "" {
		return errors.New("HOST_SCOPE_FIXED: changing the authorized account requires a new local installation")
	}
	return nil
}

func managedReady(ctx context.Context, base string) error {
	d, err := agentSession(base)
	if err != nil {
		return err
	}
	var state guiState
	if err = agentCall(ctx, d, "state", nil, &state); err != nil {
		return err
	}
	if !state.Managed || !state.Running {
		return errors.New("HOST_SERVICE_STARTING")
	}
	return nil
}
