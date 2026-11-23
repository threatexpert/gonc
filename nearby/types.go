// Package nearby discovers Gonc devices on the local network, pairs them by
// numeric comparison, and authenticates later transfer sessions between
// paired devices.
//
// The package holds only live state. The application owns its identity
// (installation ID, identity resolving key, nickname), the saved pairing
// records, and every user decision. The gonc CLI does not import this package.
package nearby

import (
	"errors"
	"time"
)

const ProtocolVersion = 1

var (
	ErrBusy         = errors.New("nearby: device is busy")
	ErrNotPaired    = errors.New("nearby: device does not recognize this pairing")
	ErrRejected     = errors.New("nearby: pairing was rejected")
	ErrTimeout      = errors.New("nearby: timed out")
	ErrUnknown      = errors.New("nearby: unknown device")
	ErrClosed       = errors.New("nearby: service closed")
	ErrVerification = errors.New("nearby: device could not be verified")
	// ErrQuickRefused means the device does not accept files from devices
	// it is not paired with.
	ErrQuickRefused = errors.New("nearby: device does not accept files from unpaired devices")
)

// Identity describes this installation. InstallationID and IRK must stay the
// same across restarts; create them once with NewInstallationID and NewIRK.
type Identity struct {
	InstallationID string
	IRK            []byte
	Nickname       string
	DeviceType     string // desktop, laptop, phone, tablet or server
}

// PeerRecord is a saved pairing. The application stores it as a secret.
type PeerRecord struct {
	InstallationID string    `json:"installationId"`
	IRK            []byte    `json:"irk"`
	PairKey        []byte    `json:"pairKey"`
	PairID         string    `json:"pairId"`
	Nickname       string    `json:"nickname"`
	DeviceType     string    `json:"deviceType"`
	PairedAt       time.Time `json:"pairedAt"`
}

func (r PeerRecord) valid() bool {
	return validInstallationID(r.InstallationID) && len(r.IRK) == irkBytes && len(r.PairKey) == keyBytes && r.PairID != ""
}

// Device is one entry of the nearby device list.
type Device struct {
	ID         string   `json:"id"`
	Nickname   string   `json:"nickname"`
	DeviceType string   `json:"deviceType"`
	Addresses  []string `json:"addresses"`
	PeerID     string   `json:"peerId,omitempty"`
	Paired     bool     `json:"paired"`
	Verified   bool     `json:"verified"`
	// QuickReceive is true when the device accepts offers from devices it
	// is not paired with (see OpenQuickTransfer).
	QuickReceive bool      `json:"quickReceive"`
	LastSeen     time.Time `json:"lastSeen"`
}

// Handler receives events that need the application's attention. Calls are
// made from service goroutines and must not block for long.
type Handler interface {
	DevicesChanged(devices []Device)
	IncomingPairing(p *Pairing)
	IncomingTransfer(t *IncomingTransfer)
}
