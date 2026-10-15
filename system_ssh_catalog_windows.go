package main

import (
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type sshCatalogInfo struct {
	Size uint32
	Path [260]uint16
}
type sshTrustCatalog struct {
	Size, Version      uint32
	Catalog, Tag, Path *uint16
	File               windows.Handle
	Hash               *byte
	HashSize           uint32
	Context, Admin     uintptr
}

func verifySSHCatalog(path string) error {
	dll := windows.NewLazySystemDLL("wintrust.dll")
	acquire := dll.NewProc("CryptCATAdminAcquireContext2")
	release := dll.NewProc("CryptCATAdminReleaseContext")
	calculate := dll.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	enum := dll.NewProc("CryptCATAdminEnumCatalogFromHash")
	infoProc := dll.NewProc("CryptCATCatalogInfoFromContext")
	releaseCatalog := dll.NewProc("CryptCATAdminReleaseCatalogContext")
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	member, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	for _, algorithm := range []string{"SHA256", "SHA1"} {
		alg, _ := windows.UTF16PtrFromString(algorithm)
		var admin uintptr
		ok, _, _ := acquire.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(alg)), 0, 0)
		if ok == 0 {
			continue
		}
		var size uint32
		_, _, _ = calculate.Call(admin, f.Fd(), uintptr(unsafe.Pointer(&size)), 0, 0)
		if size == 0 || size > 128 {
			release.Call(admin, 0)
			continue
		}
		hash := make([]byte, size)
		ok, _, _ = calculate.Call(admin, f.Fd(), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0)
		if ok == 0 {
			release.Call(admin, 0)
			continue
		}
		var previous uintptr
		catalog, _, _ := enum.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, uintptr(unsafe.Pointer(&previous)))
		if catalog == 0 {
			release.Call(admin, 0)
			continue
		}
		info := sshCatalogInfo{Size: uint32(unsafe.Sizeof(sshCatalogInfo{}))}
		ok, _, _ = infoProc.Call(catalog, uintptr(unsafe.Pointer(&info)), 0)
		if ok == 0 {
			releaseCatalog.Call(admin, catalog, 0)
			release.Call(admin, 0)
			continue
		}
		tag, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash[:size])))
		cat := sshTrustCatalog{Size: uint32(unsafe.Sizeof(sshTrustCatalog{})), Catalog: &info.Path[0], Tag: tag, Path: member, File: windows.Handle(f.Fd()), Hash: &hash[0], HashSize: size, Admin: admin}
		data := windows.WinTrustData{Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_CATALOG, StateAction: windows.WTD_STATEACTION_VERIFY, FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&cat)}
		err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
		releaseCatalog.Call(admin, catalog, 0)
		release.Call(admin, 0)
		runtime.KeepAlive(f)
		runtime.KeepAlive(hash)
		runtime.KeepAlive(tag)
		runtime.KeepAlive(info)
		if err == nil {
			return nil
		}
	}
	return errors.New("signed Windows catalog not found or not trusted")
}
