package apps

import (
	"context"
	"errors"
	"sync"
)

var errP2PCandidateSuperseded = errors.New("P2P candidate superseded by LAN connection")

type pendingP2PCandidate struct {
	mu     sync.Mutex
	next   uint64
	token  uint64
	cancel context.CancelCauseFunc
}

func (candidate *pendingP2PCandidate) arm(cancel context.CancelCauseFunc) uint64 {
	if cancel == nil {
		return 0
	}

	candidate.mu.Lock()
	previousCancel := candidate.cancel
	candidate.next++
	if candidate.next == 0 {
		candidate.next++
	}
	token := candidate.next
	candidate.token = token
	candidate.cancel = cancel
	candidate.mu.Unlock()

	if previousCancel != nil {
		previousCancel(errP2PCandidateSuperseded)
	}
	return token
}

func (candidate *pendingP2PCandidate) disarm(token uint64) bool {
	if token == 0 {
		return false
	}

	candidate.mu.Lock()
	defer candidate.mu.Unlock()
	if candidate.token != token {
		return false
	}
	candidate.token = 0
	candidate.cancel = nil
	return true
}

func (candidate *pendingP2PCandidate) cancelCurrent(cause error) bool {
	candidate.mu.Lock()
	cancel := candidate.cancel
	candidate.token = 0
	candidate.cancel = nil
	candidate.mu.Unlock()

	if cancel == nil {
		return false
	}
	if cause == nil {
		cause = context.Canceled
	}
	cancel(cause)
	return true
}
