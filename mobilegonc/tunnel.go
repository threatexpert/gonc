package mobilegonc

import "github.com/threatexpert/gonc/v2/goncembed"

// StartP2PTunnel starts gonc in link mode and exposes a linkConfig.
func StartP2PTunnel(password string, useUDP bool, linkConfig string, extraArgs string, cb Callback) (*Session, error) {
	session, err := goncembed.StartP2PTunnel(password, useUDP, linkConfig, extraArgs, cb)
	if err != nil {
		return nil, err
	}
	return &Session{inner: session}, nil
}

// StartP2PLinkAgent starts gonc in linkagent (dual proxy service) mode.
func StartP2PLinkAgent(password string, useUDP bool, upstream string, dnsForward string, extraArgs string, cb Callback) (*Session, error) {
	session, err := goncembed.StartP2PLinkAgent(password, useUDP, upstream, dnsForward, extraArgs, cb)
	if err != nil {
		return nil, err
	}
	return &Session{inner: session}, nil
}
