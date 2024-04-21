package configuration

import (
	"fmt"
	"net"
)

// QoL feature to try and detect the best NIC for hyp
func getDefaultNIC() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces on this system: %v", err)
	}
	if len(ifaces) < 1 {
		return nil, fmt.Errorf("this system has no network interfaces: %v", err)
	}

	// Just pick one to start
	selectedIface := ifaces[0]
	filteredIfaces := make([]net.Interface, 0)

	// Check for ethernet addresses
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 6 {
			selectedIface = iface
			filteredIfaces = append(filteredIfaces, iface)
		}
	}
	ifaces = filteredIfaces
	filteredIfaces = make([]net.Interface, 0)

	// Check for interfaces that are up and not loopbacks
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagRunning != 0 && iface.Flags&net.FlagLoopback == 0 {
			selectedIface = iface
			filteredIfaces = append(filteredIfaces, iface)
		}
	}
	ifaces = filteredIfaces
	filteredIfaces = make([]net.Interface, 0)

	// Check for interfaces that have IPv4 addresses assigned
	for _, iface := range ifaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				selectedIface = iface
				filteredIfaces = append(filteredIfaces, iface)
			}
		}
	}
	ifaces = filteredIfaces
	filteredIfaces = nil

	// Check for interfaces that have non RFC1918 addresses assigned
	for _, iface := range ifaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			if !ip.IsPrivate() {
				selectedIface = iface

			}
		}
	}

	return &selectedIface, nil // TBD
}
