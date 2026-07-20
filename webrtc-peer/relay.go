// SPDX-License-Identifier: Apache-2.0
//
// A disposable authenticated TURN server used only by the loopback exit gate.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/pion/webrtc/v4"
)

const (
	relaySelfTestVersion = "sippycup.dev/webrtc-relay-self-test/v1"
	relayRealm           = "sippycup.loopback.invalid"
	relayUsername        = "fixture-user"
	relayPassword        = "fixture-password-not-a-target-secret"
)

func runRelaySelfTest(arguments []string) error {
	flags := flag.NewFlagSet("relay-self-test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	timeout := flags.Duration("timeout", 20*time.Second, "hard relay deadline")
	portMin := flags.Uint("port-min", 42000, "first allowed peer UDP port")
	portMax := flags.Uint("port-max", 42199, "last allowed peer UDP port")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("relay-self-test accepts no positional arguments")
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

	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.Writer = io.Discard
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: relayRealm,
		AuthHandler: func(
			attributes *turn.RequestAttributes,
		) (string, []byte, bool) {
			if attributes.Username != relayUsername ||
				attributes.Realm != relayRealm {
				return "", nil, false
			}
			return relayUsername, turn.GenerateAuthKey(
				relayUsername,
				relayRealm,
				relayPassword,
			), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: listener,
			RelayAddressGenerator: &turn.RelayAddressGeneratorNone{
				Address: "127.0.0.1",
			},
		}},
		LoggerFactory:      loggerFactory,
		AllocationLifetime: time.Minute,
		PermissionTimeout:  time.Minute,
		ChannelBindTimeout: time.Minute,
	})
	if err != nil {
		_ = listener.Close()
		return err
	}
	defer server.Close()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rec := &recorder{start: start}
	report := selfTestReport{
		APIVersion:      relaySelfTestVersion,
		Kind:            "WebRTCRelaySelfTest",
		Status:          "fail",
		NetworkActivity: true,
		NetworkScope:    "loopback-turn",
		Limits: limits{
			DeadlineSeconds: int(timeout.Seconds()),
			Packets:         packetCount,
			PayloadBytes:    payloadBytes,
			PortMin:         int(*portMin),
			PortMax:         int(*portMax),
		},
	}
	configuration := webrtc.Configuration{
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
		ICEServers: []webrtc.ICEServer{{
			URLs:       []string{"turn:" + listener.LocalAddr().String() + "?transport=udp"},
			Username:   relayUsername,
			Credential: relayPassword,
		}},
	}
	checks, testErr := exercisePeerCall(
		ctx,
		rec,
		uint16(*portMin),
		uint16(*portMax),
		configuration,
		true,
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
