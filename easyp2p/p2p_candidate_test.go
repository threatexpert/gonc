package easyp2p

import "testing"

func reportedMultiExitTCPAddresses() ([]PunchingAddressInfo, []PunchingAddressInfo) {
	localA := []PunchingAddressInfo{
		{Network: "tcp4", Lan: "10.192.156.114:64568", Nat: "106.39.145.5:43320", NatType: "hard"},
		{Network: "tcp4", Lan: "10.192.156.114:64568", Nat: "223.71.76.129:3336", NatType: "symm"},
	}
	localB := []PunchingAddressInfo{
		{Network: "tcp4", Lan: "10.192.156.114:64571", Nat: "106.39.145.5:40070", NatType: "symm"},
		{Network: "tcp4", Lan: "10.192.156.114:64571", Nat: "223.71.76.129:30144", NatType: "hard"},
	}
	return localA, localB
}

func TestCanonicalLANProbeSelectionKeepsPeerRolesComplementary(t *testing.T) {
	localA, localB := reportedMultiExitTCPAddresses()

	_, candidatesA, _ := buildBaseP2PCandidates(localA, localB, true)
	_, candidatesB, _ := buildBaseP2PCandidates(localB, localA, true)
	selectedA := selectLANProbeCandidate(candidatesA, true)
	selectedB := selectLANProbeCandidate(candidatesB, true)

	if selectedA == nil || selectedB == nil {
		t.Fatalf("canonical selection returned nil: A=%+v B=%+v", selectedA, selectedB)
	}
	if selectedA.Network != selectedB.Network ||
		selectedA.LocalLAN != selectedB.RemoteLAN ||
		selectedA.LocalNAT != selectedB.RemoteNAT ||
		selectedA.LocalNATType != selectedB.RemoteNATType ||
		selectedA.RemoteLAN != selectedB.LocalLAN ||
		selectedA.RemoteNAT != selectedB.LocalNAT ||
		selectedA.RemoteNATType != selectedB.LocalNATType {
		t.Fatalf("canonical candidates are not mirrors:\nA=%+v\nB=%+v", selectedA, selectedB)
	}

	sessCtx := &P2PSessionContext{}
	if SelectRole(selectedA, sessCtx) == SelectRole(selectedB, sessCtx) {
		t.Fatalf("mirrored candidates selected the same role:\nA=%+v\nB=%+v", selectedA, selectedB)
	}
}

func TestLANProbeSelectionMirrorsLegacyPeerTraversal(t *testing.T) {
	localA, localB := reportedMultiExitTCPAddresses()

	_, candidatesA, _ := buildBaseP2PCandidates(localA, localB, true)
	selectedA := selectLANProbeCandidate(candidatesA, false)

	if selectedA == nil {
		t.Fatal("legacy-compatible selection returned nil")
	}
	if selectedA.LocalNAT != "223.71.76.129:3336" ||
		selectedA.RemoteNAT != "106.39.145.5:40070" ||
		selectedA.LocalNATType != "symm" ||
		selectedA.RemoteNATType != "symm" {
		t.Fatalf("selected candidate does not mirror legacy peer traversal: %+v", selectedA)
	}
}
