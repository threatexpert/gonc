//go:build gonc_noexec

package apps

// ExecSupported is false: this build was made with -tags gonc_noexec and
// cannot start local processes. See checkExecFeatures.
const ExecSupported = false
