//go:build !gonc_noexec

package apps

// ExecSupported is true: this build can run local programs. See
// checkExecFeatures for what the gonc_noexec build tag leaves out.
const ExecSupported = true
