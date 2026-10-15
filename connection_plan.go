package main

import (
	"errors"
	"os"
	"path/filepath"
)

// Desired local configuration, separate from live health and secret material.
type connectionPlan struct {
	Version int        `json:"version"`
	Role    string     `json:"role"`
	Host    guiRequest `json:"host"`
	Caller  guiRequest `json:"caller"`
	Resume  bool       `json:"resume"`
}

func readConnectionPlan(base string) (connectionPlan, error) {
	var p connectionPlan
	err := readJSON(filepath.Join(base, "connection-plan.json"), &p)
	if err == nil {
		if p.Version != 1 {
			return p, errors.New("CONNECTION_PLAN_VERSION_UNSUPPORTED")
		}
		return p, nil
	}
	if !os.IsNotExist(err) {
		return p, err
	}
	p.Version = 1
	// Old files are configuration hints, never proof of elevated authorization.
	var grant sshGrant
	if readJSON(filepath.Join(base, "public-host", "ssh-grant.json"), &grant) == nil {
		p.Host = guiRequest{Role: "host", User: grant.User, AllowSSH: true}
		p.Role = "host"
	}
	if _, err := os.Stat(filepath.Join(base, "public-connect", "config.json")); err == nil {
		p.Caller.Role = "connect"
		var login sshLogin
		if readJSON(filepath.Join(base, "ssh-login.json"), &login) == nil {
			p.Caller.User, p.Caller.KeyPath = login.User, login.KeyPath
		}
		if p.Role == "" {
			p.Role = "connect"
		}
	}
	return p, nil
}

func (p connectionPlan) request(role string) guiRequest {
	if role == "host" {
		return p.Host
	}
	return p.Caller
}

func (g *guiSession) resolveRequest(r guiRequest) (guiRequest, error) {
	p, err := readConnectionPlan(g.base)
	if err != nil {
		return r, err
	}
	if r.Role == "" {
		r.Role = p.Role
	}
	if r.Role != "host" && r.Role != "connect" {
		return r, errors.New("CONNECTION_NOT_CONFIGURED")
	}
	saved := p.request(r.Role)
	if r.Target == "" {
		r.Target = saved.Target
	}
	if r.Listen == "" {
		r.Listen = saved.Listen
	}
	if r.User == "" {
		r.User = saved.User
	}
	if r.KeyPath == "" {
		r.KeyPath = saved.KeyPath
	}
	if saved.ManualSSH {
		r.ManualSSH = true
	}
	if r.Role == "host" {
		r.AllowSSH = r.AllowSSH || saved.AllowSSH
		if r.Privilege == "" {
			r.Privilege = saved.Privilege
		}
	}
	return r, nil
}

func (g *guiSession) savePlan(r guiRequest, resume bool) error {
	p, err := readConnectionPlan(g.base)
	if err != nil {
		return err
	}
	p.Version, p.Role, p.Resume = 1, r.Role, resume
	r.ConnectionKey, r.Fingerprint, r.RequestID = "", "", ""
	if r.Role == "host" {
		p.Host = r
	} else {
		p.Caller = r
	}
	return privateJSON(filepath.Join(g.base, "connection-plan.json"), p)
}

func (g *guiSession) restorePlanDisplay() {
	p, err := readConnectionPlan(g.base)
	if err != nil {
		g.state.Problem = &connectionProblem{Code: "CONNECTION_PLAN_INVALID", Side: "local", Message: "本机配置无法读取", NextAction: "检查 connection-plan.json，保留原身份"}
		return
	}
	if p.Role != "" {
		g.state.Role = p.Role
	}
	r := p.request(g.state.Role)
	g.state.AuthorizedUser = p.Host.User
	g.state.Privilege = p.Host.Privilege
	if a, err := readHostAuthorization(filepath.Join(g.base, "public-host")); err == nil {
		g.state.SSHEngine = a.Engine
		g.state.Privilege = a.Privilege
	}
	if g.state.Role == "host" {
		g.state.Address = r.Target
	} else {
		g.state.Address = r.Listen
	}
	g.state.Configured = p.Role != ""
}
