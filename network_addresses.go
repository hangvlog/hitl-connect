package main

import (
	"net"
	"net/netip"
	"sort"
)

// Report only active, unicast interface addresses. No interface names, MACs,
// DNS configuration or network scanning are collected.
func localAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addresses []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		entries, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, entry := range entries {
			addresses = append(addresses, entry.String())
		}
	}
	return normalizedLocalAddresses(addresses)
}

func normalizedLocalAddresses(entries []string) []string {
	seen := map[string]bool{}
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if ip.IsGlobalUnicast() {
			seen[ip.String()] = true
		}
	}
	result := make([]string, 0, len(seen))
	for ip := range seen {
		result = append(result, ip)
	}
	sort.Strings(result)
	if len(result) > 16 {
		result = result[:16]
	}
	return result
}
