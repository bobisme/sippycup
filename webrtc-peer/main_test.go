package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestCanaryPayloadIsDeterministicAndDistinct(t *testing.T) {
	first := canaryPayload(0)
	repeated := canaryPayload(0)
	second := canaryPayload(1)
	if !bytes.Equal(first, repeated) {
		t.Fatal("same packet index produced different payloads")
	}
	if bytes.Equal(first, second) {
		t.Fatal("adjacent packet payloads must differ")
	}
	if len(first) != payloadBytes {
		t.Fatalf("payload length = %d, want %d", len(first), payloadBytes)
	}

	hash := sha256.New()
	for index := 0; index < packetCount; index++ {
		hash.Write(canaryPayload(index))
	}
	if got, want := hex.EncodeToString(hash.Sum(nil)),
		"7390f38421a29be2eb3d217b6d3886bb478acaff3228c9a4271c0e85221be836"; got != want {
		t.Fatalf("canary digest = %s, want %s", got, want)
	}
}

func TestCapabilityContractIsNetworkFreeAndStable(t *testing.T) {
	report := capabilityReport{
		APIVersion:            capabilityVersion,
		Kind:                  "WebRTCAdapterCapabilities",
		Implementation:        "pion-webrtc",
		ImplementationVersion: buildVersion,
		BuildCommit:           buildCommit,
		SourceDigest:          buildSourceDigest,
		Capabilities:          append([]string(nil), capabilities...),
		VerifiedCapabilities:  append([]string(nil), verifiedCapabilities...),
		NetworkActivity:       false,
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, required := range []string{
		`"apiVersion":"sippycup.dev/webrtc-adapter-capabilities/v1"`,
		`"networkActivity":false`,
		`"dtls-srtp"`,
		`"ice-restart"`,
		`"turn-tls"`,
		`"verifiedCapabilities":["audio","wss-signaling","trickle-ice","ice-restart","dtls-srtp","rtcp"]`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("capability report does not contain %s", required)
		}
	}
}

func TestLoopbackSignalingSelfTestIsBoundedAndFixedVocabulary(t *testing.T) {
	adapter := newLoopbackSignalingAdapter()
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	checks := exerciseSignalingFixture(ctx, wssURL, rootCAs)
	if len(checks) != 12 {
		t.Fatalf("checks = %d, want 12", len(checks))
	}
	for _, item := range checks {
		if !item.Passed {
			t.Fatalf("check %s failed: observed=%v detail=%s", item.ID, item.Observed, item.Detail)
		}
	}
	counters := adapter.snapshot()
	if counters.Connections > 12 || counters.Messages > 24 {
		t.Fatalf("fixture exceeded bounds: %+v", counters)
	}
}

func TestLoopbackSelfTestExercisesBoundedEncryptedAudio(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rec := &recorder{start: time.Now()}
	checks, err := exerciseLoopback(ctx, rec, 41200, 41399)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 6 {
		t.Fatalf("checks = %d, want 6", len(checks))
	}
	for _, item := range checks {
		if !item.Passed {
			t.Fatalf("check %s did not pass", item.ID)
		}
	}
	encoded, err := json.Marshal(rec.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(encoded))
	for _, forbidden := range []string{
		"a=ice-pwd:",
		"a=fingerprint:",
		"candidate:",
		"127.0.0.1",
		"::1",
		"private key",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("event output leaked forbidden value %q", forbidden)
		}
	}
}

func TestLoopbackPortRangeIsNarrow(t *testing.T) {
	if _, err := loopbackAPI(42000, 41999); err == nil {
		t.Fatal("inverted UDP range unexpectedly succeeded")
	}
}
