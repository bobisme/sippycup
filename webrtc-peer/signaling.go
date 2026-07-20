// SPDX-License-Identifier: Apache-2.0
//
// The built-in signaling adapter is a loopback fixture. It intentionally has
// no target URL, path, header, cookie, or arbitrary message input.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

const (
	signalingSelfTestVersion = "sippycup.dev/wss-signaling-self-test/v1"
	fixtureAdapterID         = "sippycup.loopback-wss"
	fixtureAdapterVersion    = "1.0.0"
	allowedBrowserOrigin     = "https://allowed.example.test"
	foreignBrowserOrigin     = "https://foreign.example.test"
	maxFixtureMessageBytes   = 512
	maxFixtureMessages       = 4
)

type signalingRequest struct {
	Operation string `json:"operation"`
	Session   string `json:"session,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Value     string `json:"value,omitempty"`
}

type signalingResponse struct {
	Outcome      string `json:"outcome"`
	SessionState string `json:"sessionState"`
}

type signalingCounters struct {
	Connections int `json:"connections"`
	Messages    int `json:"messages"`
	AuthFailure int `json:"authFailures"`
}

type signalingAdapterIdentity struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type signalingSelfTestReport struct {
	APIVersion               string                   `json:"apiVersion"`
	Status                   string                   `json:"status"`
	NetworkActivity          bool                     `json:"networkActivity"`
	NetworkScope             string                   `json:"networkScope"`
	Adapter                  signalingAdapterIdentity `json:"adapter"`
	Checks                   []check                  `json:"checks"`
	Counters                 signalingCounters        `json:"counters"`
	OpenConnections          int                      `json:"openConnections"`
	SecretsRetained          bool                     `json:"secretsRetained"`
	RawMessagesRetained      bool                     `json:"rawMessagesRetained"`
	ArbitraryMessagesEnabled bool                     `json:"arbitraryMessagesEnabled"`
}

type loopbackSignalingAdapter struct {
	mu              sync.Mutex
	nonces          map[string]struct{}
	acceptForeign   bool
	connections     int
	openConnections int
	messages        int
	authFailures    int
}

func newLoopbackSignalingAdapter() *loopbackSignalingAdapter {
	return &loopbackSignalingAdapter{nonces: make(map[string]struct{})}
}

func (a *loopbackSignalingAdapter) handshake(
	_ *websocket.Config,
	request *http.Request,
) error {
	if request.Header.Get("Origin") != allowedBrowserOrigin {
		if a.acceptForeign && request.Header.Get("Origin") == foreignBrowserOrigin {
			a.mu.Lock()
			a.connections++
			a.openConnections++
			a.mu.Unlock()
			return nil
		}
		return errors.New("origin denied")
	}
	a.mu.Lock()
	a.connections++
	a.openConnections++
	a.mu.Unlock()
	return nil
}

func (a *loopbackSignalingAdapter) serve(connection *websocket.Conn) {
	defer func() {
		a.mu.Lock()
		a.openConnections--
		a.mu.Unlock()
		_ = connection.Close()
	}()
	state := "pre-auth"
	role := ""
	count := 0
	for {
		var raw []byte
		if err := websocket.Message.Receive(connection, &raw); err != nil {
			return
		}
		count++
		a.mu.Lock()
		a.messages++
		a.mu.Unlock()
		if len(raw) > maxFixtureMessageBytes {
			sendSignalingResponse(connection, "rejected", state)
			return
		}
		if count > maxFixtureMessages {
			sendSignalingResponse(connection, "rate-limited", state)
			return
		}
		var request signalingRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			sendSignalingResponse(connection, "rejected", state)
			return
		}
		switch request.Operation {
		case "hello":
			if state != "pre-auth" {
				sendSignalingResponse(connection, "rejected", state)
				return
			}
			if request.Session == "" || request.Nonce == "" {
				a.mu.Lock()
				a.authFailures++
				a.mu.Unlock()
				sendSignalingResponse(connection, "denied", state)
				return
			}
			a.mu.Lock()
			_, replayed := a.nonces[request.Nonce]
			if !replayed {
				a.nonces[request.Nonce] = struct{}{}
			}
			a.mu.Unlock()
			if replayed {
				sendSignalingResponse(connection, "rejected", state)
				return
			}
			if request.Session == "expired" {
				sendSignalingResponse(connection, "expired", "expired")
				return
			}
			if request.Session != "viewer" && request.Session != "operator" {
				a.mu.Lock()
				a.authFailures++
				a.mu.Unlock()
				sendSignalingResponse(connection, "denied", state)
				return
			}
			role = request.Session
			state = "authenticated"
			sendSignalingResponse(connection, "allowed", state)
		case "read":
			if state != "authenticated" {
				sendSignalingResponse(connection, "rejected", state)
				return
			}
			sendSignalingResponse(connection, "allowed", state)
		case "write":
			if state != "authenticated" {
				sendSignalingResponse(connection, "rejected", state)
				return
			}
			if role != "operator" {
				sendSignalingResponse(connection, "denied", state)
				continue
			}
			sendSignalingResponse(connection, "allowed", state)
		case "close":
			sendSignalingResponse(connection, "closed", "closed")
			return
		default:
			sendSignalingResponse(connection, "rejected", state)
			return
		}
	}
}

func sendSignalingResponse(
	connection *websocket.Conn,
	outcome string,
	state string,
) {
	_ = websocket.JSON.Send(connection, signalingResponse{
		Outcome:      outcome,
		SessionState: state,
	})
}

func (a *loopbackSignalingAdapter) snapshot() signalingCounters {
	a.mu.Lock()
	defer a.mu.Unlock()
	return signalingCounters{
		Connections: a.connections,
		Messages:    a.messages,
		AuthFailure: a.authFailures,
	}
}

func (a *loopbackSignalingAdapter) open() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.openConnections
}

func runSignalingSelfTest(arguments []string) error {
	flags := flag.NewFlagSet("signaling-self-test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	timeout := flags.Duration("timeout", 10*time.Second, "hard loopback deadline")
	seedFailure := flags.String(
		"seed-failure",
		"",
		"local negative control: origin-accept",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("signaling-self-test accepts no positional arguments")
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		return errors.New("timeout must be between 1s and 30s")
	}
	if *seedFailure != "" && *seedFailure != "origin-accept" {
		return errors.New("seed-failure must be origin-accept")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	adapter := newLoopbackSignalingAdapter()
	adapter.acceptForeign = *seedFailure == "origin-accept"
	server := httptest.NewUnstartedServer(websocket.Server{
		Handshake: adapter.handshake,
		Handler:   adapter.serve,
	})
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	wssURL := "wss" + strings.TrimPrefix(server.URL, "https")

	checks := exerciseSignalingFixture(ctx, wssURL, rootCAs)
	status := "pass"
	for _, item := range checks {
		if !item.Passed {
			status = "fail"
			break
		}
	}
	for deadline := time.Now().Add(500 * time.Millisecond); adapter.open() != 0; {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	report := signalingSelfTestReport{
		APIVersion:      signalingSelfTestVersion,
		Status:          status,
		NetworkActivity: true,
		NetworkScope:    "loopback",
		Adapter: signalingAdapterIdentity{
			ID:      fixtureAdapterID,
			Version: fixtureAdapterVersion,
		},
		Checks:                   checks,
		Counters:                 adapter.snapshot(),
		OpenConnections:          adapter.open(),
		SecretsRetained:          false,
		RawMessagesRetained:      false,
		ArbitraryMessagesEnabled: false,
	}
	if report.OpenConnections != 0 {
		report.Status = "fail"
		report.Checks = append(report.Checks, check{
			ID: "clean-disconnect", Passed: false, Detail: "connection leak",
		})
	}
	if err := encode(os.Stdout, report); err != nil {
		return err
	}
	if report.Status != "pass" {
		return errors.New("signaling self-test failed")
	}
	return nil
}

func exerciseSignalingFixture(
	ctx context.Context,
	wssURL string,
	rootCAs *x509.CertPool,
) []check {
	var checks []check
	appendCheck := func(id string, expected string, observed string, err error) {
		passed := err == nil && observed == expected
		item := check{ID: id, Passed: passed, Expected: expected, Observed: observed}
		if err != nil {
			item.Detail = err.Error()
		}
		checks = append(checks, item)
	}

	_, err := dialSignaling(ctx, wssURL, allowedBrowserOrigin, nil)
	appendCheck("tls-validation", "untrusted-certificate-rejected", errorClass(err), nil)

	foreignConnection, err := dialSignaling(
		ctx,
		wssURL,
		foreignBrowserOrigin,
		rootCAs,
	)
	if foreignConnection != nil {
		_ = foreignConnection.Close()
	}
	appendCheck("origin-enforcement", "handshake-rejected", errorClass(err), nil)

	run := func(
		id string,
		requests []signalingRequest,
		expected string,
	) {
		connection, dialErr := dialSignaling(
			ctx, wssURL, allowedBrowserOrigin, rootCAs,
		)
		if dialErr != nil {
			appendCheck(id, expected, "dial-error", dialErr)
			return
		}
		defer connection.Close()
		observed := ""
		for _, request := range requests {
			if sendErr := websocket.JSON.Send(connection, request); sendErr != nil {
				appendCheck(id, expected, "send-error", sendErr)
				return
			}
			var response signalingResponse
			if receiveErr := websocket.JSON.Receive(connection, &response); receiveErr != nil {
				appendCheck(id, expected, "receive-error", receiveErr)
				return
			}
			observed = response.Outcome
		}
		appendCheck(id, expected, observed, nil)
	}
	run(
		"authentication-required",
		[]signalingRequest{{Operation: "hello"}},
		"denied",
	)
	run(
		"session-expiry",
		[]signalingRequest{{Operation: "hello", Session: "expired", Nonce: "expiry-1"}},
		"expired",
	)
	run(
		"message-authorization",
		[]signalingRequest{
			{Operation: "hello", Session: "viewer", Nonce: "role-1"},
			{Operation: "write"},
		},
		"denied",
	)
	run(
		"malformed-state-transition",
		[]signalingRequest{{Operation: "write"}},
		"rejected",
	)
	run(
		"replay-first-use",
		[]signalingRequest{{Operation: "hello", Session: "viewer", Nonce: "replay-1"}},
		"allowed",
	)
	run(
		"replay-rejection",
		[]signalingRequest{{Operation: "hello", Session: "viewer", Nonce: "replay-1"}},
		"rejected",
	)
	run(
		"size-limit",
		[]signalingRequest{{
			Operation: "hello",
			Session:   "viewer",
			Nonce:     "size-1",
			Value:     strings.Repeat("x", maxFixtureMessageBytes),
		}},
		"rejected",
	)
	run(
		"rate-limit",
		[]signalingRequest{
			{Operation: "hello", Session: "operator", Nonce: "rate-1"},
			{Operation: "read"},
			{Operation: "read"},
			{Operation: "read"},
			{Operation: "read"},
		},
		"rate-limited",
	)
	run(
		"clean-reconnect-first",
		[]signalingRequest{
			{Operation: "hello", Session: "viewer", Nonce: "reconnect-1"},
			{Operation: "close"},
		},
		"closed",
	)
	run(
		"clean-reconnect-second",
		[]signalingRequest{
			{Operation: "hello", Session: "viewer", Nonce: "reconnect-2"},
			{Operation: "read"},
		},
		"allowed",
	)
	return checks
}

func dialSignaling(
	ctx context.Context,
	wssURL string,
	origin string,
	rootCAs *x509.CertPool,
) (*websocket.Conn, error) {
	config, err := websocket.NewConfig(wssURL, origin)
	if err != nil {
		return nil, err
	}
	config.TlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "example.com",
		RootCAs:    rootCAs,
	}
	return config.DialContext(ctx)
}

func errorClass(err error) string {
	if err == nil {
		return "connected"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "certificate"):
		return "untrusted-certificate-rejected"
	case strings.Contains(text, "bad status"):
		return "handshake-rejected"
	default:
		return fmt.Sprintf("error:%T", err)
	}
}
