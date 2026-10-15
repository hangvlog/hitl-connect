package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"net/http"
)

var loginUserPattern = regexp.MustCompile(`^[a-zA-Z0-9_.@\\-]{1,128}$`)

func probeSSH(address string, algorithms ...string) (ssh.PublicKey, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	var captured ssh.PublicKey
	_, _, _, err = ssh.NewClientConn(conn, address, &ssh.ClientConfig{User: "probe", HostKeyAlgorithms: algorithms, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		captured = key
		return errors.New("host key captured; no account authentication attempted")
	}, Timeout: 8 * time.Second})
	if captured != nil {
		return captured, nil
	}
	return nil, err
}

func (g *guiSession) diagnose(request guiRequest) error {
	if request.User == "" && request.KeyPath == "" {
		var saved sshLogin
		if readJSON(filepath.Join(g.base, "ssh-login.json"), &saved) == nil {
			request.User, request.KeyPath = saved.User, saved.KeyPath
		}
	}
	g.mu.Lock()
	role, address, running := g.state.Role, g.address, g.state.Running
	g.state.LoginIdentity = ""
	g.state.NativeSSHExitCode = nil
	g.state.LoginCheckEngine = ""
	g.state.CanTrust = false
	g.mu.Unlock()
	if !running {
		return errors.New("请先启动连接，再执行检查")
	}
	g.step("login", "pending", "尚未验证账号登录")
	if role == "host" {
		var key ssh.PublicKey
		var err error
		if _, ok := embeddedPolicy(filepath.Join(g.base, "public-host")); ok {
			var embedded *embeddedSSH
			embedded, err = loadEmbeddedSSH(filepath.Join(g.base, "public-host"))
			if err == nil {
				key = embedded.signers[0].PublicKey()
			}
		} else {
			key, err = probeSSH(address)
		}
		if err != nil {
			g.step("local", "failed", "本机 HITL Connect 已不可连接，请检查服务状态")
			return nil
		}
		g.step("local", "passed", "本机 HITL Connect 服务可连接")
		g.mu.Lock()
		g.state.Fingerprint = ssh.FingerprintSHA256(key)
		g.mu.Unlock()
		c, err := load(filepath.Join(g.base, "public-host", "config.json"))
		if err != nil {
			return errors.New("尚未生成有效的提供端配置")
		}
		u, err := relayURL(c)
		if err != nil {
			return errors.New("中继地址无效")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ws, res, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + c.Token}}})
		if err != nil {
			status := 0
			if res != nil {
				status = res.StatusCode
			}
			g.step("relay", "failed", fmt.Sprintf("中继握手失败（HTTP %d）。本机进程运行不等于中继已连接", status))
			return nil
		}
		ws.CloseNow()
		g.step("relay", "passed", "中继实时握手通过，设备登记有效")
		g.step("login", "pending", "访问端会自动验证 whoami；等待访问端报告真实登录结果")
		return nil
	}
	g.step("tunnel", "working", "正在穿过中继，检查远端真实 HITL Connect 服务")
	knownFile := filepath.Join(g.base, "gui-known-hosts")
	if g.diagnoseManagedLogin(request, address, knownFile) {
		return nil
	}
	key, err := probeSSHForSavedHost(address, knownFile)
	if err != nil {
		g.step("tunnel", "failed", "未到达远端 HITL Connect 服务。请结合中继状态，检查提供端进程与本机 HITL Connect 服务")
		return nil
	}
	g.step("relay", "passed", "已通过中继建立端到端加密通道")
	g.step("tunnel", "passed", "已到达远端 HITL Connect 服务；这还不等于账号登录成功")
	fingerprint := ssh.FingerprintSHA256(key)
	g.mu.Lock()
	g.candidate = key
	g.state.Fingerprint = fingerprint
	g.state.CanTrust = false
	g.mu.Unlock()
	check, checkErr := knownhosts.New(knownFile)
	if checkErr != nil && !os.IsNotExist(checkErr) {
		g.step("login", "failed", "已保存的 HITL Connect 主机信任文件无法读取或格式错误，已阻止登录；请检查原文件")
		return nil
	}
	addr, _ := net.ResolveTCPAddr("tcp", address)
	if checkErr == nil {
		checkErr = check(address, addr, key)
	}
	if checkErr != nil {
		var ke *knownhosts.KeyError
		unknown := os.IsNotExist(checkErr) || (errors.As(checkErr, &ke) && len(ke.Want) == 0)
		if !unknown {
			g.step("login", "failed", "HITL Connect 主机密钥变化或已撤销，已阻止登录。请先核对目标电脑，未自动替换旧密钥")
			return nil
		}
		g.mu.Lock()
		g.state.CanTrust = true
		g.mu.Unlock()
		g.step("login", "attention", "首次连接：请与提供方核对下方主机指纹，确认信任后再测试登录")
		return nil
	}
	if strings.TrimSpace(request.User) == "" {
		g.step("login", "pending", "HITL Connect 主机已信任。填写远端账号后，再点击“检查连接”测试实际登录")
		return nil
	}
	if !loginUserPattern.MatchString(request.User) {
		return errors.New("远端账号格式不正确")
	}
	g.step("login", "working", "正在用本机已有 HITL Connect 密钥执行远端 whoami")
	ctx, cancel := context.WithTimeout(context.Background(), loginCheckTimeout)
	defer cancel()
	host, port, _ := net.SplitHostPort(address)
	// ssh parses -o values as config text, so an unquoted path containing
	// spaces becomes several files. Use a fixed relative name in the profile
	// directory; this also avoids config expansion of user directory names.
	args := []string{"-F", "none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=gui-known-hosts", "-o", "GlobalKnownHostsFile=none", "-o", "ConnectTimeout=30"}
	if request.KeyPath != "" {
		if stat, e := os.Stat(request.KeyPath); e != nil || !stat.Mode().IsRegular() {
			g.step("login", "failed", "指定的 HITL Connect 私钥文件不存在或不可读")
			return nil
		}
		keyPath, e := filepath.Abs(request.KeyPath)
		if e != nil {
			return e
		}
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", keyPath)
	}
	args = append(args, "-p", port, "-l", request.User, host, "whoami")
	g.mu.Lock()
	g.state.LoginCheckEngine = "native"
	g.mu.Unlock()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Dir = g.base
	// A nil stdin uses NUL on Windows. Win32 OpenSSH may then never send
	// channel EOF, leaving the embedded worker waiting after whoami returns.
	// An empty reader gives the child a pipe that os/exec closes at EOF.
	cmd.Stdin = strings.NewReader("")
	hideGUIChild(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	return g.finishLoginCheck(ctx, output, stderr.Bytes(), err)
}

func (g *guiSession) finishLoginCheck(ctx context.Context, output, stderr []byte, err error) error {
	if err != nil {
		code := 255
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			code = failure.ExitCode()
		}
		var remoteFailure *ssh.ExitError
		if errors.As(err, &remoteFailure) {
			code = remoteFailure.ExitStatus()
		}
		g.mu.Lock()
		g.state.NativeSSHExitCode = &code
		g.mu.Unlock()
		output = stderr
		for _, reason := range []string{"AUTHORIZED_ACCOUNT_NOT_LOGGED_ON", "ACCOUNT_PRIVILEGE_UNAVAILABLE", "ACCOUNT_PRIVILEGE_MISMATCH", "AUTHORIZED_ACCOUNT_CHANGED_OR_DISABLED", "AUDIT_UNAVAILABLE"} {
			if strings.Contains(string(output), reason) {
				g.connectionError(errors.New(reason))
				return nil
			}
		}
		message := "HITL Connect 登录失败；未得到远端 whoami 的成功结果"
		switch {
		case errors.Is(err, exec.ErrNotFound):
			message = "未找到本机系统连接客户端"
		case ctx.Err() != nil:
			message = "HITL Connect 登录检查超时（35 秒），已结束检查"
		case strings.Contains(string(output), "HOST IDENTIFICATION HAS CHANGED"):
			message = "HITL Connect 主机密钥变化，已阻止登录"
		case strings.Contains(string(output), "Load key"), strings.Contains(string(output), "UNPROTECTED PRIVATE KEY"):
			message = "本机 HITL Connect 私钥无法使用，请检查文件格式、权限或解锁密钥代理"
		case strings.Contains(string(output), "Permission denied"), strings.Contains(err.Error(), "unable to authenticate"):
			message = "远端拒绝 HITL Connect 登录凭据。通道已通；请核对远端账号、公钥安装位置与 ACL。此检查不会尝试 Windows 密码"
		}
		g.step("login", "failed", message)
		g.event("账号登录检查未通过")
		return nil
	}
	identity := strings.TrimSpace(string(output))
	if identity == "" || len(identity) > 256 || strings.ContainsAny(identity, "\r\n") {
		g.step("login", "failed", "HITL Connect 命令未返回有效身份，未判定为登录成功")
		return nil
	}
	g.mu.Lock()
	if !g.state.Running {
		g.mu.Unlock()
		return errors.New("客户端已退出，请重新启动后验证")
	}
	g.state.LoginIdentity = identity
	code := 0
	g.state.NativeSSHExitCode = &code
	g.state.Problem = nil
	g.stepLocked("login", "passed", "真实远端 whoami 执行成功，退出码 0")
	g.mu.Unlock()
	g.event("远端账号登录验证通过")
	return nil
}

func (g *guiSession) trust(fingerprint string) error {
	g.mu.Lock()
	key, address, allowed := g.candidate, g.address, g.state.CanTrust
	g.mu.Unlock()
	if !allowed || key == nil || ssh.FingerprintSHA256(key) != fingerprint {
		return errors.New("主机指纹状态已变化，请重新检查")
	}
	file := filepath.Join(g.base, "gui-known-hosts")
	old, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("无法读取已保存的 HITL Connect 主机信任")
	}
	if len(old) > 0 {
		if _, err = knownhosts.New(file); err != nil {
			return errors.New("原 HITL Connect 主机信任文件格式错误，未覆盖或追加")
		}
		old = append(old, '\n')
	}
	if err = privateText(file, string(old)+knownhosts.Line([]string{address}, key)+"\n"); err != nil {
		return errors.New("无法保存 HITL Connect 主机信任")
	}
	g.mu.Lock()
	g.state.CanTrust = false
	g.mu.Unlock()
	g.step("login", "pending", "已保存核对后的主机指纹；填写账号并再次检查即可测试登录")
	return nil
}
