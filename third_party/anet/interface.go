package anet

import "net"

// Interfaces returns a list of the system's network interfaces.
func Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

// InterfaceAddrs returns a list of the system's unicast interface addresses.
func InterfaceAddrs() ([]net.Addr, error) {
	return net.InterfaceAddrs()
}

// InterfaceByIndex returns the interface specified by index.
func InterfaceByIndex(index int) (*net.Interface, error) {
	return net.InterfaceByIndex(index)
}

// InterfaceByName returns the interface specified by name.
func InterfaceByName(name string) (*net.Interface, error) {
	return net.InterfaceByName(name)
}

// InterfaceAddrsByInterface returns unicast addresses for one interface.
func InterfaceAddrsByInterface(ifi *net.Interface) ([]net.Addr, error) {
	return ifi.Addrs()
}

// SetAndroidVersion is kept for API compatibility with github.com/wlynxg/anet.
func SetAndroidVersion(version uint) {}
