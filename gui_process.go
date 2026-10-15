package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func (g *guiSession) start(request guiRequest) error {
	if request.Role == "host" {
		if err := prepareProviderRelay(g.base, request.Relay); err != nil {
			return err
		}
	}
	if request.Role == "host" && request.AllowSSH {
		if handled, err := g.installManagedHost(request); handled {
			return err
		}
	}
	if request.Role != "host" && request.Role != "connect" {
		return errors.New("请选择连接方式")
	}
	g.mu.Lock()
	running := g.state.Running
	g.mu.Unlock()
	if running {
		return errors.New("请先停止当前连接，再切换模式")
	}
	address := request.Listen
	if request.Role == "host" {
		address = request.Target
		if address == "" {
			address = "127.0.0.1:22"
		}
	} else if address == "" {
		address = "127.0.0.1:2222"
	}
	address, err := loopback(address)
	if err != nil {
		return errors.New("地址必须是本机回环地址和有效端口")
	}
	g.mu.Lock()
	g.reset(request.Role)
	if request.AllowSSH {
		g.state.AuthorizedUser = request.User
	}
	g.address = address
	g.state.Address = address
	g.autoSSH, g.sshIdentity = request.Role == "connect" && !request.ManualSSH, request.KeyPath
	g.generation++
	generation := g.generation
	g.mu.Unlock()
	dir := filepath.Join(g.base, "public-"+request.Role)
	if request.Role == "host" && request.AllowSSH {
		if strings.TrimSpace(request.User) == "" {
			return errors.New("请选择允许登录的本机账号")
		}
		g.step("local", "working", "正在准备账号与 HITL Connect 服务；Windows 将请求一次管理员授权")
	} else if request.Role == "host" {
		key, probeErr := probeSSH(address)
		if probeErr != nil {
			g.step("local", "failed", "本机 HITL Connect 服务不可用。请检查 系统连接组件 是否已安装并启动。")
			return errors.New("本机 HITL Connect 服务未就绪，尚未开始配对")
		}
		g.mu.Lock()
		g.state.Fingerprint = ssh.FingerprintSHA256(key)
		g.mu.Unlock()
		g.step("local", "passed", "本机 HITL Connect 服务可连接")
	} else {
		listener, e := net.Listen("tcp", address)
		if e != nil {
			g.step("local", "failed", "本地映射端口已被占用。可能是旧客户端仍在运行，可停止旧窗口或换一个端口。")
			return errors.New("本地映射端口被占用")
		}
		listener.Close()
		if _, err = os.Stat(filepath.Join(dir, "config.json")); os.IsNotExist(err) && strings.TrimSpace(request.ConnectionKey) == "" {
			return errors.New("首次连接请粘贴提供方的连接码")
		}
		if request.ConnectionKey == "" {
			if pending, e := os.ReadFile(filepath.Join(g.base, "pending-connection-code.txt")); e == nil {
				request.ConnectionKey = strings.TrimSpace(string(pending))
			}
		}
		if request.ConnectionKey != "" && (!strings.HasPrefix(strings.TrimSpace(request.ConnectionKey), "hitl1.") || len(request.ConnectionKey) > 4096) {
			return errors.New("连接码格式不正确")
		}
		// A fresh code for the same pinned provider updates only the device-bound
		// grant. It must never replace the caller's device or SSH identity.
		if request.ConnectionKey != "" {
			if e := privateText(filepath.Join(g.base, "pending-connection-code.txt"), request.ConnectionKey); e != nil {
				return e
			}
			key, e := parseConnectionKey(request.ConnectionKey)
			if e != nil {
				return e
			}
			if c, e := load(filepath.Join(dir, "config.json")); e == nil && len(c.Peers) > 0 {
				peer, ok := c.Peers[key.Provider]
				cert, e := peerCert(key.Provider, peer.Certificate)
				if !ok || e != nil || c.Relay != key.Relay || key.Service != "ssh" {
					return errors.New("连接码属于不同设备，请使用独立身份目录")
				}
				pin := sha256.Sum256(cert.Raw)
				if hex.EncodeToString(pin[:]) != key.Fingerprint {
					return errors.New("提供方身份已变化，未替换现有信任")
				}
				if e = privateText(filepath.Join(dir, "ssh-grant.txt"), key.SSHGrant); e != nil {
					return e
				}
			}
		}
		g.step("local", "passed", "本地端口可用，正在启动映射")
	}
	if request.Role == "host" {
		if c, e := load(filepath.Join(dir, "config.json")); e == nil && c.Protocol == "v3" {
			request.Target = address
			return g.startProviderV3(request, c)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{request.Role, "--dir", dir}
	if request.Role == "host" {
		args = append(args, "--target", address)
		if request.AllowSSH {
			args = append(args, "--allow-user", request.User)
		}
	} else {
		args = append(args, "--listen", address)
	}
	cmd := exec.CommandContext(ctx, g.exe, args...)
	hideGUIChild(cmd)
	cmd.Stdin = strings.NewReader(strings.TrimSpace(request.ConnectionKey) + "\n")
	out, errout, wait, err := startGUICommand(ctx, cmd, request.AllowSSH, g.base)
	if err != nil {
		cancel()
		g.step("local", "failed", err.Error())
		return err
	}
	done := make(chan struct{})
	g.mu.Lock()
	g.child = cmd
	g.cancel = cancel
	g.done = done
	g.state.Running = true
	g.mu.Unlock()
	if request.Role == "host" {
		request.Target = address
	} else {
		request.Listen = address
	}
	if err := g.savePlan(request, true); err != nil {
		cancel()
		out.Close()
		errout.Close()
		_ = wait()
		g.mu.Lock()
		g.child = nil
		g.state.Running = false
		g.mu.Unlock()
		close(done)
		return err
	}
	g.mu.Lock()
	g.state.Configured = true
	g.mu.Unlock()
	g.step("relay", "working", "正在连接中继并检查设备登记")
	g.event("已启动客户端；保留原来的设备身份")
	go func() {
		var readers sync.WaitGroup
		readers.Add(2)
		for _, stream := range []io.Reader{out, errout} {
			go func(r io.Reader) {
				defer readers.Done()
				scanner := bufio.NewScanner(r)
				scanner.Buffer(make([]byte, 4096), 16384)
				for scanner.Scan() {
					g.processLine(scanner.Text(), generation)
				}
			}(stream)
		}
		readers.Wait()
		err := wait()
		g.mu.Lock()
		if g.child == cmd {
			g.child = nil
			g.state.Running = false
			g.state.HasInvitation = false
			g.invitation = ""
			if ctx.Err() == nil {
				g.stepLocked("tunnel", "failed", "客户端已退出，当前没有活动连接；请检查前面的失败项后重新启动")
			}
		}
		g.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			g.event("客户端已退出；请查看上方标红的检查项")
		}
		unexpected := ctx.Err() == nil
		cancel()
		close(done)
		if unexpected {
			go g.recoverChild(generation)
		}
	}()
	return nil
}

func (g *guiSession) stop() {
	g.mu.Lock()
	cancel, done := g.cancel, g.done
	g.cancel = nil
	g.generation++
	g.mu.Unlock()
	if cancel != nil {
		cancel()
		if done != nil {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
	}
	g.mu.Lock()
	g.state.Running = false
	g.state.HasInvitation = false
	g.invitation = ""
	g.candidate = nil
	g.state.CanTrust = false
	g.state.LoginIdentity = ""
	g.mu.Unlock()
	g.step("tunnel", "pending", "已停止。只停止此面板启动的客户端")
	g.step("login", "pending", "当前没有活动连接")
	g.event("连接已停止；原有身份和配置保留")
}

func (g *guiSession) processLine(line string, generation uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.generation == generation
	if !current {
		return
	}
	// Raw subprocess output never enters diagnostics. In particular a host
	// prints the invitation seed; expose it only through the explicit reveal action.
	if strings.HasPrefix(line, "hitl1.") {
		g.invitation = strings.TrimSpace(line)
		g.state.HasInvitation = true
		return
	}
	switch {
	case line == "tunnel-ready" && g.state.Role == "connect":
		g.stepLocked("relay", "passed", "最近一次连接已通过中继")
		g.stepLocked("tunnel", "passed", "最近一次端到端加密与远端服务检查已通过；账号登录单独验证")
		if p := g.state.Problem; p != nil && p.Retryable && (p.Side == "network" || p.Side == "relay") {
			g.state.Problem = nil
		}
	case strings.HasPrefix(line, "local-capacity-timeout:"):
		g.eventLocked("本机并发连接已满，新连接等待 5 秒后未能接入；已有会话保持运行")
	case strings.HasPrefix(line, "allow-ready="):
		g.stepLocked("local", "passed", "账号与 HITL Connect 服务已准备好，同一连接码可供多台设备连接，新增设备不影响已有连接")
	case strings.HasPrefix(line, "allow-error="):
		problem := describeConnectionError(errors.New(strings.TrimPrefix(line, "allow-error=")))
		g.state.Problem = problem
		status := "failed"
		if problem.Retryable {
			status = "working"
		}
		g.stepLocked("local", status, problem.Message)
	case strings.HasPrefix(line, "serving device="):
		g.stepLocked("relay", "passed", "设备已登记；正在等待访问方连接")
		g.stepLocked("tunnel", "pending", "等待访问方进行真实 HITL Connect 通道检查")
	case strings.HasPrefix(line, "listening="):
		_ = os.Remove(filepath.Join(g.base, "pending-connection-code.txt"))
		g.stepLocked("local", "passed", "本地映射已启动")
		if g.autoSSH {
			g.accessEpoch++
			go g.autoSSHAccess(generation, g.accessEpoch, g.sshIdentity)
			return
		}
		go func() {
			g.op.Lock()
			defer g.op.Unlock()
			g.mu.Lock()
			valid := g.generation == generation
			g.mu.Unlock()
			if valid {
				_ = g.diagnose(guiRequest{})
			}
		}()
	case strings.HasPrefix(line, "connected peer="):
		g.stepLocked("tunnel", "passed", "已有访问方通过加密通道连接本机 HITL Connect；账号认证仍需访问方验证")
	case strings.Contains(line, "registration restored"):
		g.stepLocked("relay", "passed", "已使用原身份恢复中继登记")
		g.eventLocked("中继登记已自动恢复，无需更换连接码")
	case strings.Contains(line, "HTTP 5"), strings.Contains(line, "relay unreachable"):
		g.stepLocked("relay", "failed", "中继服务或网络不可用。客户端会尝试恢复；更换密钥不能解决此问题")
		g.stepLocked("tunnel", "pending", "等待中继恢复")
	case strings.Contains(line, "revoked"):
		g.stepLocked("relay", "failed", "设备访问已被撤销，自动重连不会恢复该权限")
	case strings.Contains(line, "HTTP 401"):
		g.stepLocked("relay", "failed", "中继没有接受设备登记，自动恢复未成功")
	case strings.Contains(line, "invitation unavailable"):
		g.stepLocked("relay", "failed", "提供方登记或连接码不可用；请检查提供方客户端状态")
	case strings.Contains(line, "HTTP 429"):
		g.stepLocked("relay", "failed", "中继容量或请求频率达到限制，请稍后重试")
	case strings.Contains(line, "HTTP 403"), strings.Contains(line, "HTTP 409"):
		g.stepLocked("relay", "failed", "登记被拒绝或与已有身份冲突；请保留身份目录并复制诊断")
	case strings.Contains(line, "relay could not pair service:"):
		g.stepLocked("relay", "passed", "中继已接受访问端登记")
		problem := describeConnectionError(pairingFromText(line))
		if g.state.Problem == nil || g.state.Problem.Retryable || !problem.Retryable {
			g.state.Problem = problem
		}
		g.stepLocked("tunnel", "failed", problem.Message)
	case strings.Contains(line, "could not pair"):
		g.stepLocked("relay", "passed", "中继已接受访问端登记")
		g.stepLocked("tunnel", "failed", "提供方未接通：检查提供方进程是否运行、HITL Connect 服务是否可用")
	case strings.HasPrefix(line, "end-to-end "):
		g.stepLocked("tunnel", "failed", line)
	case strings.Contains(line, "authentication rejected"), strings.Contains(line, "identity changed"), strings.Contains(line, "authority changed"), strings.Contains(line, "certificate"):
		g.stepLocked("tunnel", "failed", "设备证书验证失败或已变化；未自动替换已有信任")
	case strings.Contains(line, "local service"), strings.Contains(line, "bind:"):
		g.stepLocked("local", "failed", "本机服务不可用或端口被占用")
	case strings.Contains(line, "invalid connection key"):
		g.stepLocked("relay", "failed", "连接码格式不正确，请复制完整连接码")
	case strings.Contains(line, "expired"):
		g.stepLocked("relay", "failed", "设备登记或证书已过期")
	}
}
