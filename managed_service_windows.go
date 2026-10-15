package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"golang.org/x/sys/windows/svc"
	"os"
	"path/filepath"
	"time"
)

type hostService struct{ base string }

func (s *hostService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	a, e := readHostAuthorization(filepath.Join(s.base, "public-host"))
	if e != nil {
		return true, 1
	}
	servicePolicy = &a
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runGUI(ctx, s.base, "", true) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case e := <-done:
			if e != nil {
				return true, 2
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				changes <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		}
	}
}
func runManagedCommand(ctx context.Context, args []string) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	base := f.String("dir", "", "profile")
	account := f.String("allow-user", "", "authorized account")
	target := f.String("target", "127.0.0.1:22", "local SSH target")
	privilege := f.String("privilege", "", "standard or explicitly authorized administrator")
	sid := f.String("owner-sid", "", "control owner")
	name := f.String("service-name", "", "service identity")
	reportURL := f.String("install-report-url", "", "parent result endpoint")
	reportToken := f.String("install-report-token", "", "parent result capability")
	logFile := f.String("host-log", "", "installer output")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 || *base == "" {
		return errors.New("INVALID_ARGUMENT")
	}
	if args[0] == "host-service" {
		isService, e := svc.IsWindowsService()
		if e != nil {
			return e
		}
		if !isService {
			return errors.New("SERVICE_MANAGER_REQUIRED")
		}
		return svc.Run(*name, &hostService{*base})
	}
	if *logFile != "" {
		return errors.New("INSTALL_LOG_ARGUMENT_UNSUPPORTED")
	}
	stage := "install-entry"
	err := installWindowsHost(ctx, *base, *account, *target, *sid, &stage, *privilege)
	report := installReport(stage, err)
	// This executes for failures before the protected directory exists too.
	if *reportURL != "" {
		if e := sendInstallReport(*reportURL, *reportToken, report); e != nil && err == nil {
			return e
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
	return err
}
