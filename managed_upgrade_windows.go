package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Stage and verify the replacement before interrupting an existing service.
// Read errors must retain their native code (including endpoint protection
// decisions), rather than being flattened into an apparent hash mismatch.
func prepareManagedExecutable(root, source string) (string, string, error) {
	data, err := os.ReadFile(source)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	installed := filepath.Join(root, "hitl-connect-"+digest[:16]+".exe")
	if _, err = os.Stat(installed); os.IsNotExist(err) {
		if err = copyInstallFile(source, installed); err != nil {
			return "", "", err
		}
	} else if err != nil {
		return "", "", err
	}
	installedData, err := os.ReadFile(installed)
	if err != nil {
		return "", "", err
	}
	if sha256.Sum256(installedData) != sum {
		return "", "", errors.New("INSTALL_HASH_MISMATCH")
	}
	return installed, digest, nil
}

type managedServiceControl interface {
	Query() (svc.Status, error)
	Control(svc.Cmd) (svc.Status, error)
}

// Only ERROR_SERVICE_DOES_NOT_EXIST means a new installation. A service may
// remain in SCM's database after its registry configuration is removed. Keep
// that failure intact: recreating it could undo an administrator/AV rollback.
func inspectManagedService(manager *mgr.Mgr, name string, stage *string) (*mgr.Service, mgr.Config, error) {
	*stage = "open-existing-service"
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, mgr.Config{}, nil
	}
	if err != nil {
		return nil, mgr.Config{}, fmt.Errorf("HOST_SERVICE_OPEN_FAILED: OpenService: %w", err)
	}
	*stage = "read-existing-service-config"
	config, err := service.Config()
	if err != nil {
		service.Close()
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, mgr.Config{}, fmt.Errorf("HOST_SERVICE_CONFIG_MISSING: 已有服务仍在 Windows 服务管理器中，但配置读取返回找不到文件；请让设备管理员核对服务注册表及防护回滚记录。未删除或重建服务: %w", err)
		}
		return nil, mgr.Config{}, fmt.Errorf("HOST_SERVICE_CONFIG_READ_FAILED: QueryServiceConfig/QueryServiceConfig2: %w", err)
	}
	return service, config, nil
}

// Never repeat a rejected stop, and never change an in-progress administrator
// operation. No profile or service configuration may be written until this
// confirms STOPPED. A timeout leaves the state unknown for administrator review.
func stopManagedUpgrade(ctx context.Context, service managedServiceControl) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	status, err := service.Query()
	if err != nil {
		return false, err
	}
	if status.State == svc.Stopped {
		return false, nil
	}
	if status.State != svc.Running {
		return false, errors.New("HOST_SERVICE_BUSY: wait for the existing service operation to finish")
	}
	if _, err = service.Control(svc.Stop); err != nil {
		return false, err
	}
	if err = waitManagedStopped(ctx, service); err != nil {
		return false, err
	}
	return true, nil
}

func waitManagedStopped(ctx context.Context, service managedServiceControl) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("SERVICE_STOP_INCOMPLETE: %w", err)
		}
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Windows protection/app-control decisions are not transient install failures.
// They must be reported for review, not followed by an automatic restart.
func managedProtectionBlocked(err error) bool {
	return errors.Is(err, windows.ERROR_VIRUS_INFECTED) ||
		errors.Is(err, windows.ERROR_VIRUS_DELETED) ||
		errors.Is(err, windows.ERROR_ACCESS_DISABLED_BY_POLICY)
}

type managedUpgradeService interface {
	managedServiceControl
	Config() (mgr.Config, error)
	UpdateConfig(mgr.Config) error
	Start(...string) error
}

func rollbackManagedUpgrade(service managedUpgradeService, old mgr.Config, wasRunning bool, cause error, restore func() error) error {
	if cause == nil || managedProtectionBlocked(cause) {
		return nil
	}
	// Missing configuration may be an administrator or protection decision.
	if _, err := service.Config(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := stopManagedUpgrade(ctx, service); err != nil {
		return err
	}
	if err := restore(); err != nil {
		return err
	}
	if err := service.UpdateConfig(old); err != nil {
		return err
	}
	if wasRunning {
		return service.Start()
	}
	return nil
}
