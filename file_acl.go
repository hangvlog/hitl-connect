package main

import "maps"

// Compare actual filesystem permissions, not SDDL text. Windows may expand
// generic rights, reorder allow ACEs, or split effective/inheritable entries.
type fileACE struct {
	SID         string
	Type, Flags uint8
	Mask        uint32
}
type fileACL struct {
	Owner, Group string
	Protected    bool
	Entries      []fileACE
}

func fileRights(mask uint32) uint32 {
	rights := mask &^ uint32(0xf0000000)
	for generic, mapped := range map[uint32]uint32{0x80000000: 0x120089, 0x40000000: 0x120116, 0x20000000: 0x1200a0, 0x10000000: 0x1f01ff} {
		if mask&generic != 0 {
			rights |= mapped
		}
	}
	return rights
}
func fileGrants(acl fileACL) (map[string][3]uint32, bool) {
	grants := map[string][3]uint32{}
	for _, ace := range acl.Entries {
		// Fail closed on deny/object/callback/inherited/unknown ACE forms; no
		// normalization is allowed to introduce another trustee or a write right.
		if ace.Type != 0 || ace.Flags&^uint8(0x0b) != 0 || ace.SID == "" || ace.Mask == 0 {
			return nil, false
		}
		if ace.Flags&8 != 0 && ace.Flags&3 == 0 {
			return nil, false
		}
		rights := fileRights(ace.Mask)
		value := grants[ace.SID]
		if ace.Flags&8 == 0 {
			value[0] |= rights
		}
		if ace.Flags&1 != 0 {
			value[1] |= rights
		}
		if ace.Flags&2 != 0 {
			value[2] |= rights
		}
		grants[ace.SID] = value
	}
	return grants, true
}
func sameFileACL(actual, expected fileACL) bool {
	if !actual.Protected || !expected.Protected || actual.Owner != expected.Owner || actual.Group != expected.Group {
		return false
	}
	a, ok := fileGrants(actual)
	if !ok {
		return false
	}
	b, ok := fileGrants(expected)
	return ok && maps.Equal(a, b)
}
