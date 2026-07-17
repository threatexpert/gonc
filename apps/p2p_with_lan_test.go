package apps

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

func TestHTTPServerDoesNotEnableP2PWithLANMode(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
		"-httpserver", ".",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if config.p2pWithLanMode {
		t.Fatal("P2P HTTP file service enabled p2pWithLanMode without an explicit option")
	}
	if !config.useMQTTWait {
		t.Fatal("P2P HTTP file service did not retain MQTT wait mode")
	}
}

func TestHTTPServerEnablesP2PWithLANModeWhenExplicit(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
		"-httpserver", ".",
		"-p2p-with-lan",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if !config.p2pWithLanMode || !config.useMQTTWait || !config.keepOpen {
		t.Fatal("explicit -p2p-with-lan did not retain the HTTP server's passive mode")
	}
}

func TestLANPassiveFlagSelectsLANOnlyMode(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
		"-lan-passive",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if !config.useLAN || !config.useLANPassive {
		t.Fatal("-lan-passive did not select passive LAN-only mode")
	}
	if config.p2pWithLanMode || config.useMQTTWait || config.keepOpen {
		t.Fatal("-lan-passive unexpectedly enabled concurrent P2P or passive service settings")
	}
	if config.network != "tcp4" {
		t.Fatalf("network = %q, want tcp4 for LAN-only mode", config.network)
	}
}

func TestP2PWithLANDoesNotForcePassiveMode(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
		"-p2p-with-lan",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if !config.p2pWithLanMode {
		t.Fatal("-p2p-with-lan did not enable concurrent discovery")
	}
	if config.useMQTTWait || config.keepOpen || config.useLAN || config.useLANPassive {
		t.Fatal("-p2p-with-lan unexpectedly selected a role or LAN-only mode")
	}
}

func TestP2PWithLANUsesActiveApplicationRole(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
		"-p2p-with-lan",
		"-httplocal",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if !config.p2pWithLanMode || !config.useMQTTHello || config.useMQTTWait || !config.keepOpen {
		t.Fatal("active application settings did not determine active P2P with LAN mode")
	}
}

func TestPrepareNetcatConfigEnablesEmbeddedActiveP2PWithLAN(t *testing.T) {
	config, err := PrepareNetcatConfigWithOptions(
		context.Background(),
		io.Discard,
		[]string{
			"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
			"-httplocal",
		},
		RunOptions{P2PWithLANMode: true},
	)
	if err != nil {
		t.Fatalf("PrepareNetcatConfigWithOptions: %v", err)
	}
	if !config.p2pWithLanMode || !config.useMQTTHello || config.useMQTTWait || !config.keepOpen {
		t.Fatal("embedded receive options did not enable active P2P with LAN mode")
	}
}

func TestP2PWithLANPassiveCLIRequiresKeepOpen(t *testing.T) {
	_, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-p2p", "A9f#K2m!Q7x@L4v$R8p%T6z",
		"-p2p-with-lan",
		"-mqtt-wait",
	})
	if err == nil {
		t.Fatal("passive -p2p-with-lan without -keep-open was accepted")
	}
}

func TestNewP2PAndLANPassivePaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	base := &AppNetcatConfig{
		ctx:            context.Background(),
		LogWriter:      io.Discard,
		Logger:         log.New(io.Discard, "", 0),
		network:        "any",
		useMQTTWait:    true,
		useMQTTHello:   true,
		useLAN:         true,
		useLANPassive:  true,
		p2pWithLanMode: true,
		p2pReportURL:   "http://127.0.0.1/report",
		udpProtocol:    false,
	}

	p2pPath, lanPath := newP2PAndLanPassivePaths(ctx, base)
	if p2pPath.id != p2pAndLanPassivePublicPath || p2pPath.config.ctx != ctx {
		t.Fatal("P2P path did not receive the mode context")
	}
	if !p2pPath.config.useMQTTWait || !p2pPath.config.useMQTTHello {
		t.Fatal("P2P path did not retain MQTT signaling")
	}
	if p2pPath.config.useLAN || p2pPath.config.useLANPassive {
		t.Fatal("P2P path retained LAN mode")
	}
	if p2pPath.config.p2pReportURL == "" {
		t.Fatal("P2P path unexpectedly disabled status reporting")
	}

	if lanPath.id != p2pAndLanPassiveLANPath || lanPath.config.ctx != ctx {
		t.Fatal("LAN path did not receive the mode context")
	}
	if lanPath.config.useMQTTWait || lanPath.config.useMQTTHello {
		t.Fatal("LAN path still depends on MQTT signaling")
	}
	if !lanPath.config.useLAN || !lanPath.config.useLANPassive {
		t.Fatal("LAN path is not in passive LAN mode")
	}
	if lanPath.config.network != "tcp4" {
		t.Fatalf("LAN network = %q, want tcp4", lanPath.config.network)
	}
	if lanPath.config.p2pReportURL != "" || !lanPath.quiet || !lanPath.reportConnected {
		t.Fatal("LAN path visibility policy is incorrect")
	}

	if !base.p2pWithLanMode || !base.useLAN || base.network != "any" {
		t.Fatal("building path configs mutated the original config")
	}
}

func TestNewP2PAndLANPassivePathsUsesUDP4(t *testing.T) {
	base := &AppNetcatConfig{
		ctx:         context.Background(),
		LogWriter:   io.Discard,
		Logger:      log.New(io.Discard, "", 0),
		udpProtocol: true,
	}

	_, lanPath := newP2PAndLanPassivePaths(context.Background(), base)
	if lanPath.config.network != "udp4" {
		t.Fatalf("LAN network = %q, want udp4", lanPath.config.network)
	}
}

func TestNewP2PAndLANActivePaths(t *testing.T) {
	publicCtx, cancelPublic := context.WithCancel(context.Background())
	defer cancelPublic()
	lanCtx, cancelLAN := context.WithCancel(context.Background())
	defer cancelLAN()

	base := &AppNetcatConfig{
		ctx:            context.Background(),
		LogWriter:      io.Discard,
		Logger:         log.New(io.Discard, "", 0),
		network:        "any",
		useMQTTHello:   true,
		useLAN:         true,
		useLANPassive:  true,
		p2pWithLanMode: true,
		p2pReportURL:   "http://127.0.0.1/report",
	}

	publicPath, lanPath := newP2PAndLanActivePaths(publicCtx, lanCtx, base)
	if publicPath.id != p2pAndLanActivePublicPath || publicPath.config.ctx != publicCtx {
		t.Fatal("public active path identity or context is incorrect")
	}
	if !publicPath.config.useMQTTHello || publicPath.config.useLAN || publicPath.config.useLANPassive {
		t.Fatal("public active path did not retain MQTT hello or retained LAN mode")
	}
	if publicPath.config.p2pReportURL == "" || publicPath.quiet {
		t.Fatal("public active path unexpectedly disabled normal status visibility")
	}

	if lanPath.id != p2pAndLanActiveLANPath || lanPath.config.ctx != lanCtx {
		t.Fatal("LAN active path identity or context is incorrect")
	}
	if lanPath.config.useMQTTWait || lanPath.config.useMQTTHello {
		t.Fatal("LAN active path still depends on MQTT signaling")
	}
	if !lanPath.config.useLAN || lanPath.config.useLANPassive || lanPath.config.network != "tcp4" {
		t.Fatal("LAN active path is not active tcp4 LAN mode")
	}
	if lanPath.config.p2pReportURL != "" || !lanPath.quiet {
		t.Fatal("LAN active path visibility policy is incorrect")
	}

	if !base.p2pWithLanMode || !base.useLAN || !base.useLANPassive || base.network != "any" {
		t.Fatal("building active path configs mutated the original config")
	}
}

func TestNewP2PAndLANActivePathsUsesUDP4(t *testing.T) {
	base := &AppNetcatConfig{
		ctx:         context.Background(),
		LogWriter:   io.Discard,
		Logger:      log.New(io.Discard, "", 0),
		udpProtocol: true,
	}

	_, lanPath := newP2PAndLanActivePaths(context.Background(), context.Background(), base)
	if lanPath.config.network != "udp4" {
		t.Fatalf("LAN network = %q, want udp4", lanPath.config.network)
	}
}

func TestP2PAndLANActiveRaceClosesLateLoser(t *testing.T) {
	publicConn, publicPeer := negotiatedPipe(t)
	defer publicPeer.Close()
	lanConn, lanPeer := negotiatedPipe(t)
	defer lanPeer.Close()

	publicStarted := make(chan struct{})
	publicReturned := make(chan struct{})
	config := &AppNetcatConfig{
		ctx:       context.Background(),
		LogWriter: io.Discard,
		Logger:    log.New(io.Discard, "", 0),
	}
	connect := func(pathConfig *AppNetcatConfig) (*secure.NegotiatedConn, error) {
		if pathConfig.useLAN {
			<-publicStarted
			return lanConn, nil
		}
		close(publicStarted)
		<-pathConfig.ctx.Done()
		close(publicReturned)
		return publicConn, nil
	}

	winner, err := establishP2PAndLANActiveConnection(config, false, connect)
	if err != nil {
		t.Fatalf("establishP2PAndLANActiveConnection: %v", err)
	}
	defer winner.cancel()
	defer winner.conn.Close()
	if winner.path.id != p2pAndLanActiveLANPath || winner.conn != lanConn {
		t.Fatal("LAN connection did not win the controlled race")
	}

	select {
	case <-publicReturned:
	case <-time.After(time.Second):
		t.Fatal("public loser did not observe cancellation")
	}
	if err := expectPeerClosed(publicPeer); err != nil {
		t.Fatalf("late public loser remained open: %v", err)
	}
	if err := expectPeerOpen(lanPeer); err != nil {
		t.Fatalf("LAN winner was closed with the loser: %v", err)
	}
}

func TestP2PAndLANActiveRaceMarksPublicLoserSuperseded(t *testing.T) {
	lanConn, lanPeer := negotiatedPipe(t)
	defer lanPeer.Close()

	publicStarted := make(chan struct{})
	publicCause := make(chan error, 1)
	config := &AppNetcatConfig{
		ctx:       context.Background(),
		LogWriter: io.Discard,
		Logger:    log.New(io.Discard, "", 0),
	}
	connect := func(pathConfig *AppNetcatConfig) (*secure.NegotiatedConn, error) {
		if pathConfig.useLAN {
			<-publicStarted
			return lanConn, nil
		}
		close(publicStarted)
		<-pathConfig.ctx.Done()
		publicCause <- context.Cause(pathConfig.ctx)
		return nil, pathConfig.ctx.Err()
	}

	winner, err := establishP2PAndLANActiveConnection(config, false, connect)
	if err != nil {
		t.Fatalf("establishP2PAndLANActiveConnection: %v", err)
	}
	defer winner.cancel()
	defer winner.conn.Close()
	if winner.path.id != p2pAndLanActiveLANPath {
		t.Fatal("LAN connection did not win the controlled race")
	}
	if cause := <-publicCause; !errors.Is(cause, errP2PCandidateSuperseded) {
		t.Fatalf("public cancellation cause = %v, want errP2PCandidateSuperseded", cause)
	}
}

func TestReportP2PPathError(t *testing.T) {
	reports := make(chan P2PStatusReport, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var report P2PStatusReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode report: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reports <- report
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	t.Run("suppresses superseded candidate", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(errP2PCandidateSuperseded)
		config := &AppNetcatConfig{
			ctx:          ctx,
			p2pReportURL: server.URL,
			Logger:       log.New(io.Discard, "", 0),
		}

		got := reportP2PPathError(config, ctx, "superseded-session", context.Canceled)
		if !errors.Is(got, errP2PCandidateSuperseded) {
			t.Fatalf("error = %v, want errP2PCandidateSuperseded", got)
		}
		select {
		case report := <-reports:
			t.Fatalf("superseded candidate emitted report: %+v", report)
		default:
		}
	})

	t.Run("reports ordinary failure", func(t *testing.T) {
		config := &AppNetcatConfig{
			ctx:          context.Background(),
			p2pReportURL: server.URL,
			Logger:       log.New(io.Discard, "", 0),
			network:      "tcp",
		}
		ordinaryErr := errors.New("mqtt timeout")

		got := reportP2PPathError(config, config.ctx, "ordinary-session", ordinaryErr)
		if !errors.Is(got, ordinaryErr) {
			t.Fatalf("error = %v, want ordinary failure", got)
		}
		select {
		case report := <-reports:
			if report.Status != "error:mqtt timeout" {
				t.Fatalf("status = %q, want %q", report.Status, "error:mqtt timeout")
			}
		case <-time.After(time.Second):
			t.Fatal("ordinary failure was not reported")
		}
	})
}

func TestRejectSupersededP2PConnectionClosesConnection(t *testing.T) {
	nconn, peer := negotiatedPipe(t)
	defer peer.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errP2PCandidateSuperseded)

	err := rejectSupersededP2PConnection(ctx, nconn)
	if !errors.Is(err, errP2PCandidateSuperseded) {
		t.Fatalf("error = %v, want errP2PCandidateSuperseded", err)
	}
	if err := expectPeerClosed(peer); err != nil {
		t.Fatalf("superseded connection remained open: %v", err)
	}
}

func TestP2PAndLANActiveRaceStopsBothWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	finished := make(chan error, 1)
	config := &AppNetcatConfig{
		ctx:       ctx,
		LogWriter: io.Discard,
		Logger:    log.New(io.Discard, "", 0),
	}
	connect := func(pathConfig *AppNetcatConfig) (*secure.NegotiatedConn, error) {
		started <- struct{}{}
		<-pathConfig.ctx.Done()
		return nil, pathConfig.ctx.Err()
	}

	go func() {
		_, err := establishP2PAndLANActiveConnection(config, true, connect)
		finished <- err
	}()
	<-started
	<-started
	cancel()

	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("active race returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active race did not stop both workers")
	}
}

func negotiatedPipe(t *testing.T) (*secure.NegotiatedConn, net.Conn) {
	t.Helper()
	conn, peer := net.Pipe()
	return &secure.NegotiatedConn{
		TopLayer:   conn,
		ConnLayers: []net.Conn{conn},
	}, peer
}

func expectPeerClosed(peer net.Conn) error {
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		return err
	}
	_, err := peer.Read(make([]byte, 1))
	if err == nil {
		return io.ErrNoProgress
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return err
	}
	return nil
}

func expectPeerOpen(peer net.Conn) error {
	if err := peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		return err
	}
	_, err := peer.Read(make([]byte, 1))
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return nil
	}
	return err
}
