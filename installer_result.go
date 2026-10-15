package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

type installerReport struct {
	Schema     string  `json:"schemaVersion"`
	OK         bool    `json:"ok"`
	Code       string  `json:"code"`
	Stage      string  `json:"stage"`
	Message    string  `json:"message"`
	NativeCode *uint32 `json:"nativeCode,omitempty"`
}
type installerError struct{ Report installerReport }

func (e *installerError) Error() string {
	r := e.Report
	message := fmt.Sprintf("%s: stage=%s; %s", r.Code, r.Stage, r.Message)
	if r.NativeCode != nil {
		message += fmt.Sprintf("; nativeCode=%d", *r.NativeCode)
	}
	return message
}
func installReport(stage string, err error) installerReport {
	r := installerReport{Schema: "hitl-connect.install.v1", OK: err == nil, Code: "HOST_INSTALL_READY", Stage: stage, Message: "后台服务已启动"}
	if err == nil {
		return r
	}
	r.Code = "HOST_INSTALL_FAILED"
	if code := strings.SplitN(err.Error(), ":", 2)[0]; regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`).MatchString(code) {
		r.Code = code
	}
	// Retain the OS reason, without disclosing paths from filesystem errors.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		r.Message = pathErr.Op + ": " + pathErr.Err.Error()
	} else {
		r.Message = err.Error()
	}
	if strings.TrimSpace(r.Message) == "" {
		r.Message = "安装进程未提供错误详情；请按失败阶段检查本机状态"
	}
	var native syscall.Errno
	if errors.As(err, &native) {
		code := uint32(native)
		r.NativeCode = &code
		if runtime.GOOS == "windows" && (code == 225 || code == 226 || code == 1260) {
			r.Code = "HOST_INSTALL_BLOCKED_BY_PROTECTION"
			r.Message = "Windows 应用控制或终端防护阻止了安装；保留失败阶段与原始错误码，由设备管理员核对防护记录后处理"
		}
	}
	return r
}
func installerOutcome(report *installerReport, processErr error) error {
	if report != nil && !report.OK {
		return &installerError{*report}
	}
	if processErr != nil {
		r := installReport("installer-process", processErr)
		if r.Code != "HOST_INSTALL_BLOCKED_BY_PROTECTION" {
			r.Code = "HOST_INSTALL_PROCESS_FAILED"
		}
		return &installerError{r}
	}
	if report == nil {
		r := installReport("installer-process", errors.New("安装进程结束，但没有返回结果；未假定安装成功"))
		r.Code = "HOST_INSTALL_RESULT_MISSING"
		return &installerError{r}
	}
	return nil
}
