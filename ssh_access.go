package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshAccessMode = "ssh-access-v1"

type sshAccessRequest struct {
	PublicKey string `json:"publicKey"`
	Grant     string `json:"grant,omitempty"`
}

// Requests are carried inside the pinned device TLS session, never via relay HTTP.
// Legacy tunnel codes only request access. Explicit device-bound grants authorize
// the locally chosen account without another provider-side approval.
type sshAccess struct {
	ID          string `json:"id"`
	Peer        string `json:"peer"`
	DeviceKey   string `json:"deviceKey"`
	PublicKey   string `json:"publicKey,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	User        string `json:"user,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
	HostKey     string `json:"hostKey,omitempty"`
	Code        string `json:"code,omitempty"`
	GrantHash   string `json:"grantHash,omitempty"` // local grant generation; never sent to callers
}

func plainSSHKey(data []byte) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || len(data) > 16384 {
		return nil, errors.New("PUBLIC_KEY_INVALID")
	}
	return key, nil
}

func accessDirectory(profile string) string { return filepath.Join(profile, "ssh-access") }

// The daemon and elevated setup CLI share one short file lock. A stale lock is
// reported, never removed speculatively while a system change may be running.
func lockAccess(profile string) (func(), error) {
	dir := accessDirectory(profile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock := filepath.Join(dir, ".lock")
	for i := 0; i < 100; i++ {
		if err := os.Mkdir(lock, 0700); err == nil {
			return func() { _ = os.Remove(lock) }, nil
		} else if !os.IsExist(err) {
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, errors.New("ACCESS_BUSY")
}

func accessPath(profile, id string) (string, error) {
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) {
		return "", errors.New("ACCESS_REQUEST_INVALID")
	}
	return filepath.Join(accessDirectory(profile), id+".json"), nil
}

func accessExpired(a sshAccess) bool {
	return a.Status == "pending" && time.Now().Unix()-a.CreatedAt > 600
}

func listSSHAccess(profile string) []sshAccess {
	result := []sshAccess{}
	entries, _ := os.ReadDir(accessDirectory(profile))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		var a sshAccess
		if readJSON(filepath.Join(accessDirectory(profile), entry.Name()), &a) == nil {
			if accessExpired(a) {
				a.Status = "expired"
			}
			a.PublicKey, a.HostKey = "", ""
			result = append(result, a)
		}
	}
	return result
}

func receiveSSHAccess(profile, peer, deviceKey, public string) (sshAccess, error) {
	key, err := plainSSHKey([]byte(public))
	if err != nil {
		return sshAccess{}, err
	}
	public = string(ssh.MarshalAuthorizedKey(key))
	digest := sha256.Sum256([]byte(peer + "\n" + deviceKey + "\n" + public))
	id := hex.EncodeToString(digest[:])
	unlock, err := lockAccess(profile)
	if err != nil {
		return sshAccess{}, err
	}
	defer unlock()
	file, _ := accessPath(profile, id)
	var a sshAccess
	if err = readJSON(file, &a); err == nil {
		if accessExpired(a) {
			// A fresh explicit connect attempt may resubmit an expired request.
			a.CreatedAt = time.Now().Unix()
			if err = privateJSON(file, a); err != nil {
				return a, err
			}
		}
		return a, nil
	} else if !os.IsNotExist(err) {
		return a, err
	}
	entries := listSSHAccess(profile)
	active := 0
	for _, existing := range entries {
		if existing.Status == "expired" {
			path, _ := accessPath(profile, existing.ID)
			_ = os.Remove(path)
		} else {
			active++
		}
	}
	if active >= 64 {
		return a, errors.New("ACCESS_REQUEST_LIMIT")
	}
	a = sshAccess{ID: id, Peer: peer, DeviceKey: deviceKey, PublicKey: public,
		Fingerprint: ssh.FingerprintSHA256(key), Status: "pending", CreatedAt: time.Now().Unix()}
	err = privateJSON(file, a)
	return a, err
}

func handleSSHAccess(c *Config, encrypted *tls.Conn, paired Paired, service Service) {
	_ = encrypted.SetDeadline(time.Now().Add(15 * time.Second))
	kind, payload, err := readFrame(encrypted)
	if err != nil || kind != 3 || len(payload) > 16384 {
		return
	}
	var request sshAccessRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		return
	}
	// Bind the approval to the authenticated device public key, not the name
	// claimed in the relay's pairing response or a renewable certificate serial.
	certs := encrypted.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	digest := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	a, err := receiveSSHAccess(filepath.Dir(c.path), paired.Peer, hex.EncodeToString(digest[:]), request.PublicKey)
	if err == nil && request.Grant != "" {
		a, err = redeemSSHGrant(c, a, request.Grant)
	}
	if err != nil {
		status := "error"
		if err.Error() == "ACCESS_BUSY" {
			status = "busy"
		}
		payload, _ = json.Marshal(map[string]string{"status": status, "code": "ACCESS_REQUEST_FAILED"})
	} else {
		a.PublicKey, a.GrantHash = "", ""
		if a.Status == "approved" {
			var key ssh.PublicKey
			var probeErr error
			if c.embedded != nil {
				key = c.embedded.signers[0].PublicKey()
			} else {
				key, probeErr = probeSSH(service.Target)
			}
			if probeErr != nil {
				a.Status = "local-ssh-unavailable"
			} else {
				a.HostKey = string(ssh.MarshalAuthorizedKey(key))
			}
		}
		payload, _ = json.Marshal(a)
	}
	_ = writeFrame(encrypted, 3, payload)
}
