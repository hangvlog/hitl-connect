package main

import (
	"errors"
	"regexp"
	"strings"
)

type connectionProblem struct {
	Code       string `json:"code"`
	Side       string `json:"side"`
	Retryable  bool   `json:"retryable"`
	Message    string `json:"message"`
	NextAction string `json:"nextAction"`
}

func describeConnectionError(err error) *connectionProblem {
	p := &connectionProblem{Code: "CONNECTION_FAILED", Side: "local", Message: err.Error(), NextAction: "查看此错误和本机配置"}
	if code := strings.SplitN(err.Error(), ":", 2)[0]; regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`).MatchString(code) {
		p.Code = code
	}
	var installation *installerError
	if errors.As(err, &installation) {
		p.NextAction = "按 installation.stage、code 和 nativeCode 检查本机安装；保留原资料与目录权限"
		if p.Code == "UAC_CANCELLED" {
			p.NextAction = "重新点击允许连接并接受 Windows 系统授权"
		}
		if strings.HasPrefix(p.Code, "SETUP_EXECUTION_POLICY_") || p.Code == "SETUP_SIGNED_SCRIPT_REQUIRED" || p.Code == "SETUP_POLICY_CHECK_FAILED" {
			p.NextAction = "实际系统 PowerShell 策略不兼容或无法核验；停止安装，交管理员确认部署方案，不换执行器或修改策略"
		}
		return p
	}
	var relay *relayFailure
	var pairing *pairingFailure
	if !errors.As(err, &pairing) {
		pairing = pairingFromText(err.Error())
	}
	if pairing != nil {
		p.Code, p.Side, p.Retryable = pairing.code, "relay", pairing.retryable
		p.Message = "中继未完成配对（" + pairing.code + "）；请保留诊断与原身份"
		p.NextAction = "检查中继拒绝原因，保留原身份与授权"
		if pairing.retryable {
			p.Message = "提供端或网络暂不可用，请在连接恢复后重试"
			p.NextAction = "提供端暂未配对，程序会在连接期限内重试；无需换码"
		}
		if pairing.code == "DATA_CHANNEL_UNAVAILABLE" {
			p.Message = "提供端控制连接在线，但数据通道暂不可用；等待通道恢复"
			p.NextAction = "连接期限内自动重试；若持续失败，检查提供端数据通道池和网络，无需重置配对"
		}
		if pairing.code == "TARGET_DENIED" || pairing.code == "SERVICE_DENIED" {
			p.Message = "目标设备或服务访问被拒绝；保留原身份与授权并核对权限"
		}
		return p
	}
	if errors.As(err, &relay) {
		p.Side = "relay"
		if relay.code == "TUNNEL_INVITATION_UNAVAILABLE" {
			p.Side = "provider"
		}
		p.Code = relay.code
		if p.Code == "" {
			p.Code = "RELAY_UNAVAILABLE"
		}
		p.Retryable = !relay.permanent && (relay.status == 0 || relay.status == 401 || relay.status == 429 || relay.status >= 500 || relay.code == "TUNNEL_INVITATION_UNAVAILABLE")
		p.NextAction = "程序会自动恢复连接，无需换码"
		if !p.Retryable {
			p.NextAction = "检查中继拒绝的原因，保留原身份"
		}
		return p
	}
	var secure *secureFailure
	if errors.As(err, &secure) {
		p.Code, p.Side, p.Retryable = "END_TO_END_VERIFICATION_FAILED", "provider", secure.retryable
		p.NextAction = "核对目标设备身份与服务绑定，保留原来的信任配置"
		if secure.retryable {
			p.Code, p.Side, p.NextAction = "CONNECTION_INTERRUPTED", "network", "连接中断，程序会自动重试；无需更换身份或连接码"
		}
		return p
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "AUTHORIZED_ACCOUNT_NOT_LOGGED_ON"):
		p.Code, p.Side, p.Retryable, p.NextAction = "AUTHORIZED_ACCOUNT_NOT_LOGGED_ON", "provider", true, "在提供端登录已授权 Windows 账号后重试；锁屏无需退出，程序不会保存密码或更改登录策略"
	case strings.Contains(s, "ACCOUNT_PRIVILEGE_UNAVAILABLE"), strings.Contains(s, "ACCOUNT_PRIVILEGE_MISMATCH"):
		p.Code, p.Side, p.NextAction = "ACCOUNT_PRIVILEGE_UNAVAILABLE", "provider", "核对本机授权权限与账号资格，必须由本机管理员重新安装授权；远程不能切换权限"
	case strings.Contains(s, "HTTP 401"), strings.Contains(s, "HTTP 429"), strings.Contains(s, "HTTP 5"), strings.Contains(s, "relay unavailable"), strings.Contains(s, "relay unreachable"):
		p.Code, p.Side, p.Retryable, p.NextAction = "RELAY_UNAVAILABLE", "relay", true, "程序会自动重新登记和连接，保留原身份"
	case strings.Contains(s, "local service"), strings.Contains(s, "LOCAL_SSH_UNAVAILABLE"), strings.Contains(s, "LOCAL_SSH_UNREACHABLE"):
		p.Code, p.Side, p.Retryable, p.NextAction = "LOCAL_SSH_UNAVAILABLE", "provider", true, "等待本机 HITL Connect 服务启动，程序会自动重试"
	case strings.Contains(s, "could not pair"):
		p.Code, p.Side, p.Retryable, p.NextAction = "PROVIDER_OFFLINE", "provider", true, "等待提供端上线，程序会自动重连"
	case strings.Contains(s, "SSH_ACCESS_RESPONSE_FAILED"), strings.Contains(s, "unexpected EOF"), s == "EOF", strings.Contains(s, "deadline exceeded"), strings.Contains(s, "connection reset"), strings.Contains(s, "broken pipe"), strings.Contains(s, "connection refused"), strings.Contains(s, "closed network"):
		p.Code, p.Side, p.Retryable, p.NextAction = "CONNECTION_INTERRUPTED", "network", true, "网络恢复后自动重试"
	case strings.Contains(s, "LOCAL_ACCOUNT_NOT_AUTHORIZED"), strings.Contains(s, "HOST_SETUP_REQUIRED"):
		p.Code, p.Side, p.NextAction = "HOST_SETUP_REQUIRED", "provider", "提供端打开新版程序，按保存的账号完成首次系统配置"
	case strings.Contains(s, "CONNECTION_CODE_DISABLED"), strings.Contains(s, "CONNECTION_CODE_INVALID_OR_REPLACED"), strings.Contains(s, "CONNECTION_CODE_ALREADY_USED"), strings.Contains(s, "CONNECTION_CODE_EXPIRED"):
		p.Code, p.Side, p.NextAction = s, "provider", "由提供端处理连接码状态，程序不会自动更换身份或恢复停用"
	case strings.Contains(s, "SSH_KEY_UNAVAILABLE"):
		p.Code, p.NextAction = "SSH_KEY_UNAVAILABLE", "检查保存的私钥路径，不生成替代钥匙"
	case strings.Contains(s, "identity changed"), strings.Contains(s, "host key changed"), strings.Contains(s, "certificate"), strings.Contains(s, "trust"):
		p.Code, p.Side, p.NextAction = "IDENTITY_VERIFICATION_FAILED", "provider", "核对目标设备身份，保留已保存的信任"
	case strings.Contains(s, "UAC_CANCELLED"):
		p.Code, p.NextAction = "UAC_CANCELLED", "重新点击允许连接并接受 Windows 系统授权"
	}
	return p
}
func (g *guiSession) connectionError(err error) bool {
	p := describeConnectionError(err)
	g.mu.Lock()
	defer g.mu.Unlock()
	status := "failed"
	if p.Retryable {
		status = "working"
	}
	step := "login"
	var installation *installerError
	if errors.As(err, &installation) {
		step = "local"
		g.state.Installation = &installation.Report
	}
	g.stepLocked(step, status, p.Message)
	g.state.Problem = p
	return p.Retryable
}
func (g *guiSession) clearConnectionError() {
	g.mu.Lock()
	g.state.Problem = nil
	g.mu.Unlock()
}
