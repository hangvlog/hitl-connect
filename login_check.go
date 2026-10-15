package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const loginCheckTimeout = 35 * time.Second

// Ask the knownhosts matcher for this address's pins, including hashed and
// wildcard entries. The placeholder is never used to authenticate a server.
// The real handshake must still call check, including its revocation check.
func savedHostAlgorithms(address string, check ssh.HostKeyCallback) []string {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil
	}
	placeholder, _ := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	var mismatch *knownhosts.KeyError
	if !errors.As(check(address, addr, placeholder), &mismatch) {
		return nil
	}
	var algorithms []string
	for _, wanted := range mismatch.Want {
		types := []string{wanted.Key.Type()}
		if wanted.Key.Type() == ssh.KeyAlgoRSA {
			types = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
		}
		for _, algorithm := range types {
			if slices.Contains(ssh.SupportedAlgorithms().HostKeys, algorithm) && !slices.Contains(algorithms, algorithm) {
				algorithms = append(algorithms, algorithm)
			}
		}
	}
	return algorithms
}

// Only the application-managed key uses the built-in client. Imported keys,
// encrypted keys and agent/default-identity selection retain native semantics.
func (g *guiSession) diagnoseManagedLogin(request guiRequest, address, knownFile string) bool {
	if request.User == "" || request.KeyPath == "" || canonicalProfile(request.KeyPath) != canonicalProfile(filepath.Join(g.base, "ssh-login.key")) {
		return false
	}
	check, err := knownhosts.New(knownFile)
	if err != nil {
		// Existing discovery reports missing/malformed trust.
		return false
	}
	algorithms := savedHostAlgorithms(address, check)
	if len(algorithms) == 0 {
		return false
	}
	if !loginUserPattern.MatchString(request.User) {
		g.step("login", "failed", "远端账号格式不正确")
		return true
	}
	// Keep the same protected-owner ACL policy as automatic key exchange. Do not
	// silently fall back to another key, an agent, or a password on failure.
	if err = protectSSHLoginFile(request.KeyPath); err != nil {
		g.step("login", "failed", "本机 HITL Connect 私钥权限检查失败，已阻止登录")
		return true
	}
	data, err := os.ReadFile(request.KeyPath)
	var signer ssh.Signer
	if err == nil {
		signer, err = ssh.ParsePrivateKey(data)
	}
	if err != nil {
		g.step("login", "failed", "本机 HITL Connect 私钥无法使用，请检查文件格式与权限")
		return true
	}
	g.step("login", "working", "正在验证已保存的主机密钥并执行远端 whoami")
	ctx, cancel := context.WithTimeout(context.Background(), loginCheckTimeout)
	defer cancel()
	var trustErr error
	output, stderr, err := runLoginCheck(ctx, address, request.User, signer, algorithms, func(host string, addr net.Addr, key ssh.PublicKey) error {
		trustErr = check(host, addr, key)
		if trustErr != nil {
			return trustErr
		}
		g.step("relay", "passed", "已通过中继建立端到端加密通道")
		g.step("tunnel", "passed", "已验证远端 HITL Connect 主机密钥")
		g.step("login", "working", "主机密钥已验证，正在执行远端 whoami")
		g.mu.Lock()
		g.candidate, g.state.Fingerprint = key, ssh.FingerprintSHA256(key)
		g.mu.Unlock()
		return nil
	})
	g.mu.Lock()
	g.state.LoginCheckEngine = "embedded"
	g.mu.Unlock()
	if trustErr != nil {
		g.step("login", "failed", "HITL Connect 主机密钥不匹配或已撤销，已阻止登录；未修改原有信任")
		return true
	}
	_ = g.finishLoginCheck(ctx, output, stderr, err)
	return true
}

type loginOutput struct {
	data     []byte
	limit    int
	overflow bool
}

func (b *loginOutput) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.limit-len(b.data) {
		b.overflow = true
	}
	if remaining := b.limit - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func runLoginCheck(ctx context.Context, address, user string, signer ssh.Signer, algorithms []string, check ssh.HostKeyCallback) ([]byte, []byte, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	transport, channels, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: check, HostKeyAlgorithms: algorithms,
	})
	if err != nil {
		return nil, nil, err
	}
	client := ssh.NewClient(transport, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer session.Close()
	stdout, stderr := &loginOutput{limit: 4096}, &loginOutput{limit: 8192}
	session.Stdout, session.Stderr = stdout, stderr
	// Explicit EOF is required by the Windows embedded account worker.
	session.Stdin = strings.NewReader("")
	err = session.Run("whoami")
	if err == nil && stdout.overflow {
		err = errors.New("remote identity output exceeds limit")
	}
	return stdout.data, stderr.data, err
}
