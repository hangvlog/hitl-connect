package main

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Called under op: one entry point for GUI, agent commands and auto-resume.
func (g *guiSession) ensureConnection(request guiRequest) error {
	r, err := g.resolveRequest(request)
	if err != nil {
		return err
	}
	g.mu.Lock()
	running, role, address := g.state.Running, g.state.Role, g.address
	g.mu.Unlock()
	if running {
		if r.Relay != "" {
			if err := prepareProviderRelay(g.base, r.Relay); err != nil {
				return err
			}
		}
		desired := r.Listen
		if r.Role == "host" {
			desired = r.Target
		}
		if r.Role != role || (desired != "" && desired != address) {
			return errors.New("CONNECTION_CONFIGURATION_CHANGED: stop before switching endpoints")
		}
		p, e := readConnectionPlan(g.base)
		if e != nil {
			return e
		}
		saved := p.request(role)
		if r.User != saved.User || r.KeyPath != saved.KeyPath || r.ManualSSH != saved.ManualSSH || r.Privilege != saved.Privilege {
			return errors.New("CONNECTION_CONFIGURATION_CHANGED: stop before switching account or key")
		}
		if r.ConnectionKey != "" {
			return errors.New("CONNECTION_CODE_CHANGE_REQUIRES_STOP")
		}
		return nil
	}
	if err = g.start(r); err != nil {
		g.connectionError(err)
		return err
	}
	return nil
}
func (g *guiSession) diagnoseConnection(request guiRequest) error {
	g.mu.Lock()
	auto, running, identity := g.autoSSH, g.state.Running, g.sshIdentity
	g.mu.Unlock()
	if !running {
		if err := g.ensureConnection(guiRequest{}); err != nil {
			return err
		}
	}
	g.mu.Lock()
	auto, identity = g.autoSSH, g.sshIdentity
	g.mu.Unlock()
	if auto {
		if request.KeyPath != "" {
			identity = request.KeyPath
		}
		again, err := g.checkSSHAccess(identity)
		if err != nil {
			g.connectionError(err)
			return nil
		}
		if again {
			g.launchAccessMonitor(identity)
		}
		return nil
	}
	return g.diagnose(request)
}
func (g *guiSession) launchAccessMonitor(identity string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.accessEpoch++
	go g.autoSSHAccess(g.generation, g.accessEpoch, identity)
}
func (g *guiSession) resumeOnOpen() {
	if servicePolicy == nil {
		// A desktop locator belongs to the existing SCM service. Opening the
		// panel must not reinstall or launch a second provider when it is offline.
		if managed, err := managedProfile(g.base); err != nil || managed != "" {
			return
		}
	}
	p, err := readConnectionPlan(g.base)
	if err != nil || !p.Resume {
		return
	}
	g.op.Lock()
	defer g.op.Unlock()
	if err = g.ensureConnection(guiRequest{}); err != nil {
		g.connectionError(err)
	}
}
func (g *guiSession) rememberStopped() {
	p, err := readConnectionPlan(g.base)
	if err != nil || p.Role == "" {
		return
	}
	p.Resume = false
	_ = privateJSON(filepath.Join(g.base, "connection-plan.json"), p)
}
func savedHostAccount(profile string) (hostAuthorization, error) {
	a, err := readHostAuthorization(profile)
	if os.IsNotExist(err) {
		if _, e := os.Stat(filepath.Join(profile, "ssh-grant.json")); e == nil {
			return a, errors.New("HOST_SETUP_REQUIRED")
		}
	}
	return a, err
}

// Resume the same desired state after a child crashes. Explicit stop changes
// generation first, so an old supervisor can never resurrect a stopped session.
func (g *guiSession) recoverChild(generation uint64) {
	time.Sleep(2 * time.Second)
	g.op.Lock()
	defer g.op.Unlock()
	g.mu.Lock()
	valid := g.generation == generation && !g.state.Running
	p := g.state.Problem
	g.mu.Unlock()
	if !valid || (p != nil && !p.Retryable) {
		return
	}
	plan, err := readConnectionPlan(g.base)
	if err != nil || !plan.Resume {
		return
	}
	g.event("后台进程退出，正在恢复原连接")
	if err = g.ensureConnection(guiRequest{}); err != nil {
		g.connectionError(err)
	}
}
