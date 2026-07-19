IMAGE ?= localhost/sippycup:latest
CAPTURE ?= work/selftest.pcap

.PHONY: build campaign-gate campaign-selftest capacity-gate chaos-exit-gate chaos-lifecycle-test chaos-profile-test chaos-topology-test envelope-analysis-test envelope-exit-gate envelope-recovery-test envelope-test full-gate learn-test matrix-gate media-analyze-test media-canary media-canary-check media-gate media-packet-golden media-send-test oracle-test report resilience-test selftest shell smoke torture-exit-gate torture-test tui-test workbench-test

build:
	"$$(./bin/container-runtime)" build --tag "$(IMAGE)" --file Containerfile .

shell:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup

smoke:
	"$$(./bin/container-runtime)" run --rm "$(IMAGE)" sippycup-smoke

report:
	./bin/report "$(CAPTURE)"

selftest:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup --isolated \
		sippycup-selftest /work/selftest.pcap

campaign-selftest:
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/sippycup --isolated \
		campaign-integration-selftest /work/campaign-selftest

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
	SIPPYCUP_IMAGE="$(IMAGE)" ./bin/chaos-exit-gate

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
	$(MAKE) oracle-test
	$(MAKE) torture-test
	$(MAKE) torture-exit-gate
	$(MAKE) tui-test
	$(MAKE) learn-test
	$(MAKE) smoke
	$(MAKE) selftest
	$(MAKE) campaign-selftest

# Includes the real rootless Podman host-isolation matrix and therefore needs
# /dev/net/tun plus the documented namespace capabilities.
full-gate: campaign-gate chaos-exit-gate

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
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 ./bin/sippycup-torture exit-gate

tui-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/tui -v

learn-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/learn -v

resilience-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/resilience -v

workbench-test:
	PYTHONPATH=lib PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_workbench tests.test_journal tests.test_advisor -v
