package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Called with g.mu held; only the locally selected account is displayed.
func (g *guiSession) refreshHostGrant() {
	if g.state.AuthorizedUser == "" || !g.state.Running {
		return
	}
	var grant sshGrant
	profile := filepath.Join(g.base, "public-host")
	if a, err := readHostAuthorization(profile); err == nil {
		g.state.SSHEngine = a.Engine
		g.state.Privilege = a.Privilege
	}
	if readJSON(filepath.Join(profile, "ssh-grant.json"), &grant) != nil || grant.User != g.state.AuthorizedUser {
		return
	}
	g.state.GrantExpires, g.state.GrantUsed, g.state.GrantDisabled = 0, false, grant.Disabled
	g.state.GrantedDevices = 0
	g.state.HasInvitation = g.invitation != "" && !grant.Disabled
	if grant.Disabled {
		g.stepLocked("login", "attention", "连接码已手动停用，所有已授权设备的 HITL 连接已撤销")
		return
	}
	configuring, failed := 0, 0
	failureCodes := ""
	for _, a := range g.state.Access {
		if !accessUsesGrant(a, grant) {
			continue
		}
		g.state.GrantUsed = true
		switch a.Status {
		case "approved":
			g.state.GrantedDevices++
		case "configuring":
			configuring++
		case "setup-failed":
			failed++
			failureCodes += " " + a.Peer + ":" + a.Code
		}
	}
	detail := fmt.Sprintf("已授权 %d 台设备，可继续分享同一连接码；真实登录结果见各访问端", g.state.GrantedDevices)
	status := "pending"
	if configuring > 0 {
		status = "working"
		detail += fmt.Sprintf("；%d 台正在自动配置", configuring)
	}
	if failed > 0 {
		status = "attention"
		detail += fmt.Sprintf("；%d 台配置失败：%s", failed, failureCodes)
	}
	g.stepLocked("login", status, detail)
}

func (g *guiSession) renewGrant() error {
	g.mu.Lock()
	account, running, role := g.state.AuthorizedUser, g.state.Running, g.state.Role
	g.mu.Unlock()
	if !running || role != "host" || account == "" {
		return errors.New("先选择账号并允许连接")
	}
	c, err := load(filepath.Join(g.base, "public-host", "config.json"))
	if err != nil {
		return err
	}
	if err = issueSSHGrant(c, account); err != nil {
		return err
	}
	code, err := os.ReadFile(localPath(c, "connection-key-ssh.txt"))
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.invitation = strings.TrimSpace(string(code))
	g.state.HasInvitation = true
	g.state.GrantUsed, g.state.GrantDisabled = false, false
	g.state.GrantedDevices = 0
	g.stepLocked("login", "pending", "已生成新连接码，等待访问端粘贴")
	return nil
}
