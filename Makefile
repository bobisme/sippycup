IMAGE ?= localhost/sippycup:latest
WEBRTC_IMAGE ?= localhost/sippycup-webrtc:latest
PRACTICE_IMAGE ?= localhost/sippycup-practice:latest
CAPTURE ?= work/selftest.pcap

.PHONY: build call-selftest campaign-gate campaign-selftest capacity-gate chaos-exit-gate chaos-lifecycle-test chaos-profile-test chaos-topology-test cli-test envelope-analysis-test envelope-exit-gate envelope-recovery-test envelope-test full-gate learn-test matrix-gate mcp-exit-gate mcp-test media-analyze-test media-canary media-canary-check media-gate media-packet-golden media-send-test oracle-test practice-build practice-gate report resilience-test selftest shell smoke torture-exit-gate torture-test tui-test web-security-test webrtc-build webrtc-selftest webrtc-test workbench-test

build:
	"$$(./bin/container-runtime)" build --tag "$(IMAGE)" --file Containerfile .
	-./bin/sippycup-go --record-build "$(IMAGE)"

shell:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup shell

smoke:
	"$$(./bin/container-runtime)" run --rm "$(IMAGE)" sippycup-smoke
	./bin/sippycup commands --format json | jq -e '.networkActivity == false' >/dev/null

report:
	./bin/sippycup report "$(CAPTURE)"

selftest:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup selftest /work/selftest.pcap

campaign-selftest:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup --isolated -- \
		campaign-integration-selftest /work/campaign-selftest

# Echo peer (127.0.0.2) and credential-rejecting stub (127.0.0.3) run inside
# the same isolated container as the real `campaign run`; loopback only.
.PHONY: campaign-softphone-selftest
campaign-softphone-selftest:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup --isolated -- \
		campaign-softphone-selftest /work/campaign-softphone-selftest

# The echo peer lives inside the same isolated container on 127.0.0.2, so the
# in-image entrypoint is driven directly; only loopback traffic is sent.
call-selftest:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup --isolated -- \
		call-integration-selftest /work/call-selftest

matrix-gate:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_campaign_matrix tests.test_covering tests.test_matrix_compile tests.test_matrix_exit_gate -v
	PYTHONDONTWRITEBYTECODE=1 python3 tools/matrix_exit_gate.py

chaos-topology-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_chaos_topology

chaos-profile-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_chaos_profiles

chaos-lifecycle-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_chaos_lifecycle

chaos-exit-gate:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup chaos-exit-gate

envelope-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_envelope -v

envelope-analysis-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_envelope_analysis -v

envelope-recovery-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_envelope_recovery -v

envelope-exit-gate:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_envelope_exit_gate -v

capacity-gate: envelope-test envelope-analysis-test envelope-recovery-test envelope-exit-gate

campaign-gate:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
	$(MAKE) cli-test
	$(MAKE) oracle-test
	$(MAKE) torture-test
	$(MAKE) torture-exit-gate
	$(MAKE) tui-test
	$(MAKE) learn-test
	$(MAKE) smoke
	$(MAKE) selftest
	$(MAKE) campaign-selftest
	$(MAKE) campaign-softphone-selftest
	$(MAKE) call-selftest

# Includes the real rootless Podman host-isolation matrix and therefore needs
# /dev/net/tun plus the documented namespace capabilities. The practice gate
# needs the optional practice image (make practice-build).
full-gate: campaign-gate chaos-exit-gate practice-gate

media-canary:
	PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_audio_canaries.py media/canary-v1

media-canary-check:
	PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_audio_canaries.py --check media/canary-v1

media-packet-golden:
	PYTHONDONTWRITEBYTECODE=1 python3 tools/generate_media_packet_golden.py

media-send-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_media_sender

media-analyze-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_media_analysis

media-gate:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_media_canary tests.test_media_sender tests.test_media_analysis tests.test_media_exit_gate -v

oracle-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/oracle -v
	PYTHONDONTWRITEBYTECODE=1 python3 tests/oracle/benchmark_oracle.py

torture-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/torture -v

torture-exit-gate:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 ./bin/sippycup torture exit-gate

tui-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/tui -v

learn-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/learn -v

resilience-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/resilience -v

workbench-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_workbench tests.test_journal tests.test_advisor tests.test_scope -v

cli-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_cli_entrypoint -v

mcp-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_mcp tests.test_mcp_capability tests.test_mcp_live_tools -v

mcp-exit-gate: mcp-test
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup mcp --exit-gate

webrtc-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_webrtc_contracts tests.test_webrtc_validation_cli tests.test_webrtc_exit_gate tests.test_webrtc_ice_turn tests.test_webrtc_sdp tests.test_webrtc_dtls_srtp tests.test_webrtc_call_evidence -v
	cd webrtc-peer && go test ./... && go vet ./...

webrtc-build:
	SIPPYCUP_IMAGE="$(IMAGE)" SIPPYCUP_WEBRTC_IMAGE="$(WEBRTC_IMAGE)" ./bin/sippycup webrtc build

webrtc-selftest:
	SIPPYCUP_WEBRTC_IMAGE="$(WEBRTC_IMAGE)" ./bin/sippycup webrtc self-test

practice-build:
	SIPPYCUP_PRACTICE_IMAGE="$(PRACTICE_IMAGE)" ./bin/sippycup practice-target build

# Live, rootless, loopback-only rehearsal against the optional Asterisk
# practice target. Starts the target when it is not already up and removes
# only what it started. Needs both images; see docs/PRACTICE-TARGET.md.
practice-gate:
	SIPPYCUP_IMAGE="$(IMAGE)" SIPPYCUP_PRACTICE_IMAGE="$(PRACTICE_IMAGE)" \
		SIPPYCUP_PRACTICE_GATE=1 SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1 \
		PYTHONDONTWRITEBYTECODE=1 \
		python3 -m unittest tests.test_practice_gate -v

# Live posture checks against the practice target (opt-in, loopback only):
# runs every runnable check and asserts the expected outcome per check.
.PHONY: checks-gate checks-test
checks-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_checks -v

checks-gate:
	SIPPYCUP_IMAGE="$(IMAGE)" SIPPYCUP_PRACTICE_IMAGE="$(PRACTICE_IMAGE)" \
		PYTHONDONTWRITEBYTECODE=1 python3 tools/checks_gate.py

# Only the fault-destination drill and its wire/verdict checks (about 2 minutes);
# `practice-gate` runs the same checks after everything else.
.PHONY: practice-drill-gate
practice-drill-gate:
	SIPPYCUP_IMAGE="$(IMAGE)" SIPPYCUP_PRACTICE_IMAGE="$(PRACTICE_IMAGE)" \
		SIPPYCUP_PRACTICE_GATE=1 SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1 \
		SIPPYCUP_PRACTICE_GATE_ONLY=faults PYTHONDONTWRITEBYTECODE=1 \
		python3 -m unittest tests.test_practice_gate -v

# Live, loopback-only softphone checks (DTMF, SRTP, registration status,
# media scope) against the practice target plus one isolated PJSUA peer.
# Opt-in like practice-gate; needs both images. See docs/PRACTICE-TARGET.md.
.PHONY: softphone-gate
softphone-gate:
	SIPPYCUP_IMAGE="$(IMAGE)" SIPPYCUP_PRACTICE_IMAGE="$(PRACTICE_IMAGE)" \
		SIPPYCUP_SOFTPHONE_GATE=1 SIPPYCUP_PRACTICE_GATE_REQUIRE_IMAGES=1 \
		PYTHONDONTWRITEBYTECODE=1 \
		python3 -m unittest tests.test_softphone_gate -v

web-security-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_web_security_contracts tests.test_web_security_evidence -v
