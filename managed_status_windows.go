package main

import (
	"errors"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Diagnostics request only query rights. They never start, recreate or change
// the service, and derive its identity instead of trusting a locator's name.
func queryManagedService(source, managed string) managedServiceStatus {
	out := managedServiceStatus{Code: "HOST_SERVICE_UNAVAILABLE", State: "UNKNOWN", Stage: "locate-service"}
	fail := func(err error) managedServiceStatus {
		var native syscall.Errno
		if errors.As(err, &native) {
			code := uint32(native)
			out.NativeCode = &code
		}
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
			out.Code = "HOST_SERVICE_CONFIG_MISSING"
		case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
			out.Code = "HOST_SERVICE_NOT_REGISTERED"
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			out.Code = "HOST_SERVICE_ACCESS_DENIED"
		}
		return out
	}
	sid, err := currentOwnerSID()
	if err != nil {
		return fail(err)
	}
	root, name, err := managedLocation(source, sid)
	if err != nil {
		return fail(err)
	}
	if managed == "" || !strings.EqualFold(canonicalProfile(root), canonicalProfile(managed)) {
		out.Code = "MANAGED_PROFILE_INVALID"
		return out
	}
	out.Stage = "open-service-manager"
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fail(err)
	}
	defer windows.CloseServiceHandle(m)
	out.Stage = "open-existing-service"
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fail(err)
	}
	h, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return fail(err)
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	out.Stage = "query-service-status"
	status, err := s.Query()
	if err != nil {
		return fail(err)
	}
	switch status.State {
	case svc.Stopped:
		out.State, out.Code = "STOPPED", "HOST_SERVICE_STOPPED"
	case svc.Running:
		out.State, out.Code = "RUNNING", "HOST_SERVICE_RUNNING_UNAVAILABLE"
	case svc.StartPending:
		out.State = "START_PENDING"
	case svc.StopPending:
		out.State = "STOP_PENDING"
	default:
		out.State = "OTHER"
	}
	out.Stage = "read-existing-service-config"
	if _, err = s.Config(); err != nil {
		out.Code = "HOST_SERVICE_CONFIG_READ_FAILED"
		return fail(err)
	}
	out.Stage = "query-service-complete"
	return out
}
