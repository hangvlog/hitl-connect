package main

import (
	"errors"
	"net"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// A server may offer several host keys. A discovery probe's preferred algorithm
// is not an identity change. If a different algorithm is already pinned, prove
// possession of that original key instead of trusting or appending the new one.
func matchSavedSSHHost(address string, offered ssh.PublicKey, check ssh.HostKeyCallback) (ssh.PublicKey, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	err = check(address, addr, offered)
	if err == nil {
		return offered, nil
	}
	var mismatch *knownhosts.KeyError
	if !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
		return nil, err
	}
	algorithms := []string{}
	for _, wanted := range mismatch.Want {
		// A changed key of an already pinned type remains a hard failure.
		if wanted.Key.Type() == offered.Type() {
			return nil, err
		}
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
	if len(algorithms) == 0 {
		return nil, err
	}
	key, probeErr := probeSSH(address, algorithms...)
	if probeErr != nil {
		return nil, probeErr
	}
	if err = check(address, addr, key); err != nil {
		return nil, err
	}
	return key, nil
}

func probeSSHForSavedHost(address, file string) (ssh.PublicKey, error) {
	key, err := probeSSH(address)
	if err != nil {
		return nil, err
	}
	check, err := knownhosts.New(file)
	if os.IsNotExist(err) {
		return key, nil
	}
	if err != nil {
		// diagnose will report malformed trust at the login step, not as an
		// unreachable tunnel. It still refuses to authenticate.
		return key, nil
	}
	verified, err := matchSavedSSHHost(address, key, check)
	if err == nil {
		return verified, nil
	}
	// Preserve the existing diagnostic/UI handling of a real mismatch, unknown
	// host or revoked key. It must never proceed to login without verification.
	return key, nil
}
