package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// The challenge contains public account/device IDs and a single-use nonce, never a login token.
func httpClaimProof(c *Config, challengeFile, output string) error {
	if challengeFile == "" || output == "" {
		return errors.New("claim-proof requires --challenge and --output")
	}
	absolute, err := filepath.Abs(output)
	if err != nil || filepath.Dir(absolute) == filepath.Dir(c.path) {
		return errors.New("proof output must be outside the provider identity directory")
	}
	if _, err := os.Lstat(absolute); !os.IsNotExist(err) {
		return errors.New("proof output already exists or cannot be inspected")
	}
	raw, err := os.ReadFile(challengeFile)
	if err != nil || len(raw) > 4096 {
		return errors.New("cannot read claim challenge")
	}
	var challenge struct {
		DeviceID string `json:"deviceId"`
		UserID   int64  `json:"userId"`
		Nonce    string `json:"nonce"`
	}
	if json.Unmarshal(raw, &challenge) != nil || challenge.DeviceID != c.ID || challenge.UserID < 1 {
		return errors.New("challenge does not match provider")
	}
	if nonce, e := hex.DecodeString(challenge.Nonce); e != nil || len(nonce) != 32 {
		return errors.New("invalid claim nonce")
	}
	key, err := tls.LoadX509KeyPair(localPath(c, c.Certificate), localPath(c, c.Key))
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(localPath(c, c.Certificate))
	if err != nil {
		return err
	}
	message, _ := json.Marshal([]any{"clawkit-connect-claim-v1", c.ID, challenge.UserID, challenge.Nonce})
	digest := sha256.Sum256(message)
	signature, err := key.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	return privateJSON(output, map[string]string{"nonce": challenge.Nonce, "certificate": string(cert), "signature": base64.StdEncoding.EncodeToString(signature)})
}
