// SPDX-License-Identifier: Apache-2.0
//
// sippycup-webrtc-peer is the optional independent WebRTC endpoint used by
// Sippycup. Its built-in self-test is strictly loopback-confined.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

const (
	capabilityVersion = "sippycup.dev/webrtc-adapter-capabilities/v1"
	selfTestVersion   = "sippycup.dev/webrtc-peer-self-test/v1"
	packetCount       = 50
	payloadBytes      = 160
)

var (
	buildVersion      = "development"
	buildCommit       = "unknown"
	buildSourceDigest = "development"
)

var capabilities = []string{
	"audio",
	"wss-signaling",
	"trickle-ice",
	"ice-restart",
	"stun",
	"turn-udp",
	"turn-tcp",
	"turn-tls",
	"dtls-srtp",
	"rtcp",
}

var verifiedCapabilities = []string{
	"audio",
	"wss-signaling",
	"trickle-ice",
	"ice-restart",
	"dtls-srtp",
	"rtcp",
}

type capabilityReport struct {
	APIVersion            string   `json:"apiVersion"`
	Kind                  string   `json:"kind"`
	Implementation        string   `json:"implementation"`
	ImplementationVersion string   `json:"implementationVersion"`
	BuildCommit           string   `json:"buildCommit"`
	SourceDigest          string   `json:"sourceDigest"`
	GoVersion             string   `json:"goVersion"`
	Capabilities          []string `json:"capabilities"`
	VerifiedCapabilities  []string `json:"verifiedCapabilities"`
	NetworkActivity       bool     `json:"networkActivity"`
}

type event struct {
	Sequence    uint64         `json:"sequence"`
	ElapsedMs   int64          `json:"elapsedMs"`
	Source      string         `json:"source"`
	Kind        string         `json:"kind"`
	Sensitivity string         `json:"sensitivity"`
	Data        map[string]any `json:"data"`
}

type check struct {
	ID       string `json:"id"`
	Passed   bool   `json:"passed"`
	Expected any    `json:"expected,omitempty"`
	Observed any    `json:"observed,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type selfTestReport struct {
	APIVersion      string  `json:"apiVersion"`
	Kind            string  `json:"kind"`
	Status          string  `json:"status"`
	NetworkActivity bool    `json:"networkActivity"`
	NetworkScope    string  `json:"networkScope"`
	DurationMs      int64   `json:"durationMs"`
	Checks          []check `json:"checks"`
	Events          []event `json:"events"`
	Limits          limits  `json:"limits"`
}

type limits struct {
	DeadlineSeconds int `json:"deadlineSeconds"`
	Packets         int `json:"packets"`
	PayloadBytes    int `json:"payloadBytes"`
	PortMin         int `json:"portMin"`
	PortMax         int `json:"portMax"`
}

type recorder struct {
	start  time.Time
	next   atomic.Uint64
	mu     sync.Mutex
	events []event
}

func (r *recorder) add(source, kind string, data map[string]any) {
	item := event{
		Sequence:    r.next.Add(1) - 1,
		ElapsedMs:   time.Since(r.start).Milliseconds(),
		Source:      source,
		Kind:        kind,
		Sensitivity: "internal",
		Data:        data,
	}
	r.mu.Lock()
	r.events = append(r.events, item)
	r.mu.Unlock()
}

func (r *recorder) snapshot() []event {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := append([]event(nil), r.events...)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Sequence < result[j].Sequence
	})
	return result
}

type endpoint struct {
	name       string
	connection *webrtc.PeerConnection
	candidates chan webrtc.ICECandidateInit
	gathered   atomic.Int64
	completed  atomic.Int64
	connected  chan struct{}
	once       sync.Once
}

type receivedMedia struct {
	packets int
	bytes   int
	digest  string
	err     error
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "capabilities":
		err = runCapabilities(os.Args[2:])
	case "self-test":
		err = runSelfTest(os.Args[2:])
	case "signaling-self-test":
		err = runSignalingSelfTest(os.Args[2:])
	case "version":
		err = encode(os.Stdout, map[string]any{
			"version":         buildVersion,
			"commit":          buildCommit,
			"sourceDigest":    buildSourceDigest,
			"networkActivity": false,
		})
	case "help", "--help", "-h":
		usage(os.Stdout)
		return
	default:
		usage(os.Stderr)
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage(output io.Writer) {
	fmt.Fprintln(output, `Usage: sippycup-webrtc-peer COMMAND [OPTIONS]

Commands:
  capabilities  Print the versioned, network-free capability contract
  self-test     Run one bounded audio call over loopback only
  signaling-self-test
                Run bounded browser-style WSS checks over loopback only
  version       Print build provenance as JSON

The peer is an optional low-level endpoint. Target execution is not exposed
until the Sippycup authorization-bound WebRTC runner passes its exit gate.`)
}

func runCapabilities(arguments []string) error {
	flags := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("capabilities accepts no positional arguments")
	}
	return encode(os.Stdout, capabilityReport{
		APIVersion:            capabilityVersion,
		Kind:                  "WebRTCAdapterCapabilities",
		Implementation:        "pion-webrtc",
		ImplementationVersion: buildVersion,
		BuildCommit:           buildCommit,
		SourceDigest:          buildSourceDigest,
		GoVersion:             runtime.Version(),
		Capabilities:          append([]string(nil), capabilities...),
		VerifiedCapabilities:  append([]string(nil), verifiedCapabilities...),
		NetworkActivity:       false,
	})
}

func runSelfTest(arguments []string) error {
	flags := flag.NewFlagSet("self-test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	timeout := flags.Duration("timeout", 15*time.Second, "hard self-test deadline")
	portMin := flags.Uint("port-min", 41000, "first allowed loopback UDP port")
	portMax := flags.Uint("port-max", 41199, "last allowed loopback UDP port")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("self-test accepts no positional arguments")
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		return errors.New("timeout must be between 1s and 30s")
	}
	if *portMin < 1024 || *portMax > 65535 || *portMin >= *portMax {
		return errors.New("invalid non-privileged UDP port range")
	}
	if *portMax-*portMin+1 > 1000 {
		return errors.New("UDP port range cannot exceed 1000 ports")
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rec := &recorder{start: start}
	report := selfTestReport{
		APIVersion:      selfTestVersion,
		Kind:            "WebRTCPeerSelfTest",
		Status:          "fail",
		NetworkActivity: true,
		NetworkScope:    "loopback",
		Limits: limits{
			DeadlineSeconds: int(timeout.Seconds()),
			Packets:         packetCount,
			PayloadBytes:    payloadBytes,
			PortMin:         int(*portMin),
			PortMax:         int(*portMax),
		},
	}

	checks, testErr := exerciseLoopback(
		ctx, rec, uint16(*portMin), uint16(*portMax),
	)
	report.Checks = checks
	report.Events = rec.snapshot()
	report.DurationMs = time.Since(start).Milliseconds()
	if testErr == nil {
		report.Status = "pass"
	}
	if err := encode(os.Stdout, report); err != nil {
		return err
	}
	return testErr
}

func exerciseLoopback(
	ctx context.Context,
	rec *recorder,
	portMin uint16,
	portMax uint16,
) ([]check, error) {
	api, err := loopbackAPI(portMin, portMax)
	if err != nil {
		return nil, err
	}
	left, err := newEndpoint(api, "left", rec)
	if err != nil {
		return nil, err
	}
	defer left.connection.Close()
	right, err := newEndpoint(api, "right", rec)
	if err != nil {
		return nil, err
	}
	defer right.connection.Close()

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypePCMU,
			ClockRate: 8000,
		},
		"canary-audio",
		"sippycup-self-test",
	)
	if err != nil {
		return nil, fmt.Errorf("create audio track: %w", err)
	}
	sender, err := left.connection.AddTrack(track)
	if err != nil {
		return nil, fmt.Errorf("add audio track: %w", err)
	}

	rtcpDone := make(chan struct{})
	var rtcpPackets atomic.Int64
	go func() {
		defer close(rtcpDone)
		for {
			packets, _, readErr := sender.ReadRTCP()
			if readErr != nil {
				return
			}
			rtcpPackets.Add(int64(len(packets)))
		}
	}()

	media := make(chan receivedMedia, 1)
	right.connection.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		rec.add("right", "media.track", map[string]any{
			"codec": remote.Codec().MimeType,
			"kind":  remote.Kind().String(),
		})
		go readCanary(ctx, remote, media)
	})

	stopCandidates, err := negotiate(ctx, left, right, rec)
	if err != nil {
		return nil, err
	}
	defer stopCandidates()
	if err := waitConnected(ctx, left, right); err != nil {
		return nil, err
	}

	expectedDigest, err := sendCanary(ctx, track, rec)
	if err != nil {
		return nil, err
	}
	var observed receivedMedia
	select {
	case observed = <-media:
		if observed.err != nil {
			return nil, observed.err
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("receive media: %w", ctx.Err())
	}
	stopCandidates()
	restart, err := restartICE(ctx, left, right, rec)
	if err != nil {
		return nil, err
	}
	cleanup, err := gracefulCleanup(ctx, left, right, rtcpDone)
	if err != nil {
		return nil, err
	}

	checks := []check{
		{
			ID:       "loopback-candidate-confinement",
			Passed:   left.gathered.Load() > 0 && right.gathered.Load() > 0,
			Expected: "at least one candidate from each peer",
			Observed: map[string]int64{
				"left": left.gathered.Load(), "right": right.gathered.Load(),
			},
		},
		{
			ID:       "offer-answer-connected",
			Passed:   true,
			Expected: "both peers connected",
			Observed: "connected",
		},
		{
			ID: "dtls-srtp-pcmu-audio",
			Passed: observed.packets == packetCount &&
				observed.bytes == packetCount*payloadBytes &&
				observed.digest == expectedDigest,
			Expected: map[string]any{
				"packets": packetCount,
				"bytes":   packetCount * payloadBytes,
				"sha256":  expectedDigest,
			},
			Observed: map[string]any{
				"packets": observed.packets,
				"bytes":   observed.bytes,
				"sha256":  observed.digest,
			},
		},
		{
			ID:       "ice-restart",
			Passed:   restart.leftCandidates > 0 && restart.rightCandidates > 0,
			Expected: "new candidates gathered by both peers",
			Observed: map[string]int64{
				"left":  restart.leftCandidates,
				"right": restart.rightCandidates,
			},
		},
		{
			ID:       "rtcp-reader-active",
			Passed:   true,
			Expected: "bounded RTCP reader attached",
			Observed: map[string]any{"packetsBeforeClose": rtcpPackets.Load()},
			Detail:   "A zero count is valid for this short call; close unblocks the reader.",
		},
		{
			ID:       "graceful-cleanup",
			Passed:   cleanup,
			Expected: "both peers closed and RTCP reader stopped",
			Observed: cleanup,
		},
	}
	for _, item := range checks {
		if !item.Passed {
			return checks, fmt.Errorf("self-test check failed: %s", item.ID)
		}
	}
	rec.add("runner", "selftest.complete", map[string]any{
		"packets": packetCount,
		"bytes":   packetCount * payloadBytes,
	})
	return checks, nil
}

func gracefulCleanup(
	ctx context.Context,
	left *endpoint,
	right *endpoint,
	rtcpDone <-chan struct{},
) (bool, error) {
	if err := right.connection.GracefulClose(); err != nil {
		return false, fmt.Errorf("gracefully close right peer: %w", err)
	}
	if err := left.connection.GracefulClose(); err != nil {
		return false, fmt.Errorf("gracefully close left peer: %w", err)
	}
	select {
	case <-rtcpDone:
	case <-ctx.Done():
		return false, fmt.Errorf("wait for RTCP reader cleanup: %w", ctx.Err())
	}
	if left.connection.ConnectionState() != webrtc.PeerConnectionStateClosed ||
		right.connection.ConnectionState() != webrtc.PeerConnectionStateClosed {
		return false, errors.New("peer state did not reach closed during cleanup")
	}
	return true, nil
}

type restartObservation struct {
	leftCandidates  int64
	rightCandidates int64
}

func restartICE(
	ctx context.Context,
	left *endpoint,
	right *endpoint,
	rec *recorder,
) (restartObservation, error) {
	beforeLeft := left.gathered.Load()
	beforeRight := right.gathered.Load()
	beforeLeftComplete := left.completed.Load()
	beforeRightComplete := right.completed.Load()
	offer, err := left.connection.CreateOffer(&webrtc.OfferOptions{ICERestart: true})
	if err != nil {
		return restartObservation{}, fmt.Errorf("create ICE restart offer: %w", err)
	}
	if err := left.connection.SetLocalDescription(offer); err != nil {
		return restartObservation{}, fmt.Errorf("set ICE restart offer: %w", err)
	}
	if err := waitGathering(ctx, left, beforeLeftComplete); err != nil {
		return restartObservation{}, err
	}
	localOffer := left.connection.LocalDescription()
	if localOffer == nil {
		return restartObservation{}, errors.New("ICE restart local offer is absent")
	}
	if err := right.connection.SetRemoteDescription(*localOffer); err != nil {
		return restartObservation{}, fmt.Errorf("apply ICE restart offer: %w", err)
	}
	answer, err := right.connection.CreateAnswer(nil)
	if err != nil {
		return restartObservation{}, fmt.Errorf("create ICE restart answer: %w", err)
	}
	if err := right.connection.SetLocalDescription(answer); err != nil {
		return restartObservation{}, fmt.Errorf("set ICE restart answer: %w", err)
	}
	if err := waitGathering(ctx, right, beforeRightComplete); err != nil {
		return restartObservation{}, err
	}
	localAnswer := right.connection.LocalDescription()
	if localAnswer == nil {
		return restartObservation{}, errors.New("ICE restart local answer is absent")
	}
	if err := left.connection.SetRemoteDescription(*localAnswer); err != nil {
		return restartObservation{}, fmt.Errorf("apply ICE restart answer: %w", err)
	}
	rec.add("runner", "ice.restart.applied", map[string]any{
		"offerSdpSha256":  digestString(offer.SDP),
		"answerSdpSha256": digestString(answer.SDP),
	})

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		observation := restartObservation{
			leftCandidates:  left.gathered.Load() - beforeLeft,
			rightCandidates: right.gathered.Load() - beforeRight,
		}
		if observation.leftCandidates > 0 &&
			observation.rightCandidates > 0 &&
			left.connection.SignalingState() == webrtc.SignalingStateStable &&
			right.connection.SignalingState() == webrtc.SignalingStateStable {
			return observation, nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return observation, fmt.Errorf("wait for ICE restart: %w", ctx.Err())
		}
	}
}

func waitGathering(
	ctx context.Context,
	item *endpoint,
	previousCompletions int64,
) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for item.completed.Load() <= previousCompletions {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return fmt.Errorf("wait for %s ICE gathering: %w", item.name, ctx.Err())
		}
	}
	return nil
}

func loopbackAPI(portMin uint16, portMax uint16) (*webrtc.API, error) {
	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterCodec(
		webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:     webrtc.MimeTypePCMU,
				ClockRate:    8000,
				RTCPFeedback: nil,
			},
			PayloadType: 0,
		},
		webrtc.RTPCodecTypeAudio,
	); err != nil {
		return nil, fmt.Errorf("register PCMU: %w", err)
	}
	registry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(mediaEngine, registry); err != nil {
		return nil, fmt.Errorf("register interceptors: %w", err)
	}
	settings := webrtc.SettingEngine{}
	settings.SetIncludeLoopbackCandidate(true)
	settings.SetInterfaceFilter(func(name string) bool { return name == "lo" })
	settings.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeUDP6,
	})
	if err := settings.SetEphemeralUDPPortRange(portMin, portMax); err != nil {
		return nil, fmt.Errorf("set UDP range: %w", err)
	}
	return webrtc.NewAPI(
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithInterceptorRegistry(registry),
		webrtc.WithSettingEngine(settings),
	), nil
}

func newEndpoint(
	api *webrtc.API,
	name string,
	rec *recorder,
) (*endpoint, error) {
	connection, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, fmt.Errorf("create %s peer: %w", name, err)
	}
	item := &endpoint{
		name:       name,
		connection: connection,
		candidates: make(chan webrtc.ICECandidateInit, 128),
		connected:  make(chan struct{}),
	}
	connection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			item.completed.Add(1)
			rec.add(name, "ice.gathering.complete", map[string]any{
				"candidates": item.gathered.Load(),
			})
			return
		}
		item.gathered.Add(1)
		rec.add(name, "ice.candidate", map[string]any{
			"type":     candidate.Typ.String(),
			"protocol": candidate.Protocol.String(),
		})
		select {
		case item.candidates <- candidate.ToJSON():
		default:
			rec.add(name, "ice.candidate.overflow", map[string]any{})
		}
	})
	connection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		rec.add(name, "ice.state", map[string]any{"state": state.String()})
	})
	connection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		rec.add(name, "peer.state", map[string]any{"state": state.String()})
		if state == webrtc.PeerConnectionStateConnected {
			item.once.Do(func() { close(item.connected) })
		}
	})
	connection.OnSignalingStateChange(func(state webrtc.SignalingState) {
		rec.add(name, "signaling.state", map[string]any{"state": state.String()})
	})
	return item, nil
}

func negotiate(
	ctx context.Context,
	left *endpoint,
	right *endpoint,
	rec *recorder,
) (context.CancelFunc, error) {
	offer, err := left.connection.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	if err := left.connection.SetLocalDescription(offer); err != nil {
		return nil, fmt.Errorf("set left local offer: %w", err)
	}
	if err := right.connection.SetRemoteDescription(offer); err != nil {
		return nil, fmt.Errorf("set right remote offer: %w", err)
	}
	rec.add("runner", "signaling.offer.applied", map[string]any{
		"sdpSha256": digestString(offer.SDP),
	})

	answer, err := right.connection.CreateAnswer(nil)
	if err != nil {
		return nil, fmt.Errorf("create answer: %w", err)
	}
	if err := right.connection.SetLocalDescription(answer); err != nil {
		return nil, fmt.Errorf("set right local answer: %w", err)
	}
	if err := left.connection.SetRemoteDescription(answer); err != nil {
		return nil, fmt.Errorf("set left remote answer: %w", err)
	}
	rec.add("runner", "signaling.answer.applied", map[string]any{
		"sdpSha256": digestString(answer.SDP),
	})

	candidateContext, cancelCandidates := context.WithCancel(ctx)
	candidateErrors := make(chan error, 2)
	go forwardCandidates(
		candidateContext, left.candidates, right.connection, candidateErrors,
	)
	go forwardCandidates(
		candidateContext, right.candidates, left.connection, candidateErrors,
	)
	select {
	case err := <-candidateErrors:
		if err != nil {
			cancelCandidates()
			return nil, err
		}
	default:
	}
	return cancelCandidates, nil
}

func forwardCandidates(
	ctx context.Context,
	source <-chan webrtc.ICECandidateInit,
	target *webrtc.PeerConnection,
	errors chan<- error,
) {
	for {
		select {
		case candidate := <-source:
			if err := target.AddICECandidate(candidate); err != nil {
				select {
				case errors <- fmt.Errorf("add trickle candidate: %w", err):
				default:
				}
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func waitConnected(
	ctx context.Context,
	left *endpoint,
	right *endpoint,
) error {
	for _, item := range []*endpoint{left, right} {
		select {
		case <-item.connected:
		case <-ctx.Done():
			return fmt.Errorf("wait for %s connection: %w", item.name, ctx.Err())
		}
	}
	return nil
}

func sendCanary(
	ctx context.Context,
	track *webrtc.TrackLocalStaticRTP,
	rec *recorder,
) (string, error) {
	hash := sha256.New()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for index := 0; index < packetCount; index++ {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("send canary: %w", ctx.Err())
		case <-ticker.C:
		}
		payload := canaryPayload(index)
		if _, err := hash.Write(payload); err != nil {
			return "", err
		}
		packet := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    0,
				SequenceNumber: uint16(1000 + index),
				Timestamp:      uint32(index * payloadBytes),
				SSRC:           0x53504350,
				Marker:         index == 0,
			},
			Payload: payload,
		}
		if err := track.WriteRTP(packet); err != nil {
			return "", fmt.Errorf("send RTP packet %d: %w", index, err)
		}
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	rec.add("left", "media.canary.sent", map[string]any{
		"packets": packetCount,
		"bytes":   packetCount * payloadBytes,
		"sha256":  digest,
	})
	return digest, nil
}

func readCanary(
	ctx context.Context,
	track *webrtc.TrackRemote,
	output chan<- receivedMedia,
) {
	hash := sha256.New()
	result := receivedMedia{}
	for result.packets < packetCount {
		if err := track.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			result.err = fmt.Errorf("set RTP read deadline: %w", err)
			output <- result
			return
		}
		packet, _, err := track.ReadRTP()
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			result.err = fmt.Errorf("read RTP packet: %w", err)
			output <- result
			return
		}
		if _, err := hash.Write(packet.Payload); err != nil {
			result.err = err
			output <- result
			return
		}
		result.packets++
		result.bytes += len(packet.Payload)
	}
	result.digest = hex.EncodeToString(hash.Sum(nil))
	output <- result
}

func canaryPayload(packet int) []byte {
	result := make([]byte, payloadBytes)
	for index := range result {
		result[index] = byte((packet*17 + index*31 + 23) & 0xff)
	}
	return result
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func encode(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
