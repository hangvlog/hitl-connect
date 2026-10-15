package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type sshLogin struct {
	User    string `json:"user"`
	KeyPath string `json:"keyPath"`
}

func accessKey(base, existing string) (string, ssh.PublicKey, error) {
	file := existing
	if file == "" {
		file = filepath.Join(base, "ssh-login.key")
	}
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) && existing == "" {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", nil, e
		}
		block, e := ssh.MarshalPrivateKey(key, "HITL SSH login")
		if e != nil {
			return "", nil, e
		}
		data = pem.EncodeToMemory(block)
		f, e := createSSHLoginFile(file)
		if e != nil {
			return "", nil, e
		}
		_, e = f.Write(data)
		err = errors.Join(e, f.Close())
	}
	if err != nil {
		return "", nil, err
	}
	if existing == "" || canonicalProfile(file) == canonicalProfile(filepath.Join(base, "ssh-login.key")) {
		if err = protectSSHLoginFile(file); err != nil {
			return "", nil, err
		}
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", nil, errors.New("SSH_KEY_UNAVAILABLE: cannot use existing key; it has not been replaced")
	}
	return file, signer.PublicKey(), nil
}

func requestSSHAccess(ctx context.Context, c *Config, public ssh.PublicKey) (sshAccess, error) {
	var result sshAccess
	peerID := ""
	for id, peer := range c.Peers {
		if slices.Contains(peer.Services, "ssh") {
			if peerID != "" {
				return result, errors.New("multiple SSH providers; use a separate profile")
			}
			peerID = id
		}
	}
	if peerID == "" {
		return result, errors.New("SSH provider is not paired")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	ws, paired, err := connect(ctx, c, Hello{Role: "dial", Target: peerID, Service: "ssh"})
	if err != nil {
		return result, err
	}
	defer ws.CloseNow()
	mode := sshAccessMode
	encrypted, err := secureWithMode(ctx, c, ws, paired, false, &mode)
	if err != nil {
		return result, fmt.Errorf("SSH_ACCESS_UNAVAILABLE: %w", err)
	}
	defer encrypted.Close()
	_ = encrypted.SetDeadline(time.Now().Add(15 * time.Second))
	grant, _ := os.ReadFile(localPath(c, "ssh-grant.txt"))
	payload, _ := json.Marshal(sshAccessRequest{PublicKey: string(ssh.MarshalAuthorizedKey(public)), Grant: strings.TrimSpace(string(grant))})
	if err = writeFrame(encrypted, 3, payload); err != nil {
		return result, err
	}
	kind, payload, err := readFrame(encrypted)
	if err != nil || kind != 3 {
		return result, errors.New("SSH_ACCESS_RESPONSE_FAILED")
	}
	if json.Unmarshal(payload, &result) != nil {
		return result, errors.New("SSH_ACCESS_RESPONSE_INVALID")
	}
	if result.Status == "busy" {
		return result, nil
	}
	if result.Fingerprint != ssh.FingerprintSHA256(public) || result.Peer != c.ID {
		return result, errors.New("SSH_ACCESS_RESPONSE_INVALID")
	}
	return result, nil
}

func trustPairedSSHHost(base, address, public string) error {
	key, err := plainSSHKey([]byte(public))
	if err != nil {
		return err
	}
	file := filepath.Join(base, "gui-known-hosts")
	old, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		check, e := knownhosts.New(file)
		if e != nil {
			return errors.New("existing SSH host trust is malformed; not overwritten")
		}
		if _, e = matchSavedSSHHost(address, key, check); e == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !errors.As(e, &ke) || len(ke.Want) != 0 {
			return errors.New("SSH host key changed; not overwritten")
		}
	}
	// The public host key came from the provider identity pinned in the connection
	// code, over authenticated TLS. This is not trust-on-first-use from SSH itself.
	return privateText(file, strings.TrimSpace(string(old))+"\n"+knownhosts.Line([]string{address}, key)+"\n")
}

func (g *guiSession) checkSSHAccess(identity string) (bool, error) {
	g.mu.Lock()
	role, running, address := g.state.Role, g.state.Running, g.address
	g.mu.Unlock()
	if !running || role != "connect" {
		return false, errors.New("start the caller first")
	}
	c, err := load(filepath.Join(g.base, "public-connect", "config.json"))
	if err != nil {
		return false, err
	}
	if identity == "" {
		p, e := readConnectionPlan(g.base)
		if e != nil {
			return false, e
		}
		identity = p.Caller.KeyPath
	}
	c.recovery = &enrollmentRecovery{}
	file, key, err := accessKey(g.base, identity)
	if err != nil {
		return false, err
	}
	a, err := requestSSHAccess(context.Background(), c, key)
	if err != nil {
		return false, err
	}
	if a.Status == "busy" {
		g.step("login", "working", "提供方正在应用授权配置，稍后自动复查")
		return true, nil
	}
	g.mu.Lock()
	g.state.Problem = nil
	g.state.AccessStatus, g.state.AccessRequest = a.Status, a.ID
	g.mu.Unlock()
	switch a.Status {
	case "configuring":
		g.step("relay", "passed", "已通过中继建立端到端加密通道")
		g.step("tunnel", "passed", "连接码授权已接受，正在自动配置登录")
		g.step("login", "working", "提供方正在安装本设备公钥，完成后自动验证登录")
		return true, nil
	case "denied", "revoked", "setup-failed":
		return false, errors.New(a.Code)
	case "pending":
		g.step("relay", "passed", "已通过中继建立端到端加密通道")
		g.step("tunnel", "passed", "公钥已自动送达提供方，等待对方确认账号授权")
		g.step("login", "attention", "等待对方确认允许登录；无需手动传公钥或输入密码")
		return true, nil
	case "rejected":
		g.step("login", "failed", "对方已拒绝此次 HITL Connect 账号授权")
		return false, nil
	case "approved":
		if err = trustPairedSSHHost(g.base, address, a.HostKey); err != nil {
			return false, err
		}
		if err = privateJSON(filepath.Join(g.base, "ssh-login.json"), sshLogin{a.User, file}); err != nil {
			return false, err
		}
		if err = g.diagnose(guiRequest{User: a.User, KeyPath: file}); err != nil {
			return false, err
		}
		g.mu.Lock()
		actual := strings.ToLower(g.state.LoginIdentity)
		expected := strings.ToLower(a.User)
		if actual != "" && actual != expected && !strings.HasSuffix(actual, "\\"+expected) {
			g.state.LoginIdentity = ""
			g.stepLocked("login", "failed", "whoami 返回了不同账号，未通过授权账号验收")
		}
		g.mu.Unlock()
		return false, nil
	default:
		return false, errors.New("provider SSH service is not ready")
	}
}

func (g *guiSession) autoSSHAccess(generation, epoch uint64, identity string) {
	delay := time.Second
	for {
		g.op.Lock()
		g.mu.Lock()
		valid := g.generation == generation && g.accessEpoch == epoch && g.state.Running
		g.mu.Unlock()
		if !valid {
			g.op.Unlock()
			return
		}
		again, err := g.checkSSHAccess(identity)
		retry := false
		if err != nil {
			retry = g.connectionError(err)
		}
		g.op.Unlock()
		if err != nil && !retry {
			return
		}
		if err == nil && !again {
			return // Approval/login is a dated result; do not poll SSH in the background.
		} else if delay > 10*time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		<-timer.C
		if err != nil && delay < 10*time.Second {
			delay *= 2
		}
	}
}
