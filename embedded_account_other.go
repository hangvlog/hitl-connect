//go:build !windows

package main

func embeddedLoginUser(policy hostAuthorization, user string) bool { return user == policy.User }
