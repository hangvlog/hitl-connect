package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

func filesystemACL(sd *windows.SECURITY_DESCRIPTOR) (fileACL, error) {
	var out fileACL
	if sd == nil || !sd.IsValid() {
		return out, errors.New("FILESYSTEM_ACL_INVALID")
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return out, errors.New("FILESYSTEM_ACL_OWNER_MISSING")
	}
	group, _, e := sd.Group()
	if e != nil || group == nil {
		return out, errors.New("FILESYSTEM_ACL_GROUP_MISSING")
	}
	control, _, e := sd.Control()
	if e != nil {
		return out, e
	}
	out.Owner, out.Group, out.Protected = owner.String(), group.String(), control&windows.SE_DACL_PROTECTED != 0
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount == 0 || acl.AceCount > 64 {
		return out, errors.New("FILESYSTEM_DACL_INVALID")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, i, &ace); e != nil {
			return out, e
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return out, errors.New("FILESYSTEM_ACE_UNSUPPORTED")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Len()+8 > int(ace.Header.AceSize) {
			return out, errors.New("FILESYSTEM_ACE_INVALID")
		}
		out.Entries = append(out.Entries, fileACE{sid.String(), ace.Header.AceType, ace.Header.AceFlags, uint32(ace.Mask)})
	}
	runtime.KeepAlive(sd)
	return out, nil
}
func equivalentFilesystemACL(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	a, e := filesystemACL(actual)
	if e != nil {
		return false
	}
	b, e := filesystemACL(expected)
	return e == nil && sameFileACL(a, b)
}
