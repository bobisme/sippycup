"""Campaign media capture (bn-24x): RTP to a media address that differs from
the signaling host is captured, counted by the watchdog, recorded per step,
stripped of payload, and approved only where the plan authorizes it.

Old manifests and frozen plans keep their bytes and validate as before.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import capture_scope  # noqa: E402
from sippycup.campaign import ManifestError, compile_plan, verify_frozen_plan  # noqa: E402
from sippycup.evidence import _authorized_networks, _classic_pcap_addresses, privacy_findings  # noqa: E402
from sippycup.integration import CaptureWatchdog, execute_campaign, strip_media_payload  # noqa: E402
from sippycup.runtime import RuntimeError as PlanError, validate_plan  # noqa: E402
from sippycup_softphone import campaign_runner  # noqa: E402
from sippycup_workbench.summary_model import Options, build_report  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "campaign"
TOOL = FIXTURES / "integration-tool.py"
FAKE_PJSUA = ROOT / "tests" / "fixtures" / "fake_pjsua.py"
SIGNALING = "10.20.30.40"
MEDIA_POOL = "10.20.40.0/28"
MEDIA_PEER = "10.20.40.5"
OUTSIDE = "10.20.40.16"


def proxy_manifest(*, media_networks: list[str] | None = (MEDIA_POOL,), networks=None) -> dict:
    """A proxy-shaped campaign: signaling to one host, media from a pool."""
    manifest = yaml.safe_load((FIXTURES / "valid.yaml").read_bytes())
    manifest["targets"][0]["address"] = SIGNALING
    manifest["authorization"]["networks"] = networks or [f"{SIGNALING}/32"]
    if media_networks is not None:
        manifest["authorization"]["mediaNetworks"] = list(media_networks)
    return manifest


def compiled(manifest: dict) -> tuple[dict, bytes]:
    raw = yaml.safe_dump(manifest, sort_keys=True).encode()
    return compile_plan(manifest, hashlib.sha256(raw).hexdigest()), raw


def canonical(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def ipv4_udp(source: str, destination: str, sport: int, dport: int, payload: bytes) -> bytes:
    import ipaddress

    total = 20 + 8 + len(payload)
    return (
        b"\x45\x00" + total.to_bytes(2, "big") + b"\0\0\0\0\x40\x11\0\0"
        + ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed
        + sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + (8 + len(payload)).to_bytes(2, "big") + b"\0\0"
        + payload
    )


def frame(linktype: int, ip: bytes) -> bytes:
    if linktype == capture_scope.LINKTYPE_ETHERNET:
        return b"\0" * 12 + b"\x08\x00" + ip
    if linktype == capture_scope.LINKTYPE_LINUX_SLL2:
        # protocol, reserved, ifindex, ARPHRD, packet type, address length, address
        return b"\x08\x00" + b"\0\0" + b"\0\0\0\1" + b"\0\1" + b"\0" + b"\x06" + b"\0" * 8 + ip
    if linktype == capture_scope.LINKTYPE_LINUX_SLL:
        return b"\0\0" + b"\0\1" + b"\0\x06" + b"\0" * 8 + b"\x08\x00" + ip
    if linktype == capture_scope.LINKTYPE_RAW:
        return ip
    raise AssertionError(linktype)


def pcap(linktype: int, packets: list[bytes]) -> bytes:
    data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype)
    for index, packet in enumerate(packets):
        data += struct.pack("<IIII", 1, index * 1000, len(packet), len(packet)) + packet
    return data


RTP = b"\x80\x00\x00\x01" + b"\0" * 8 + b"VOICE-PAYLOAD-CANARY"


def call_packets(linktype: int, media: str = MEDIA_PEER) -> list[bytes]:
    return [
        frame(linktype, ipv4_udp("10.0.0.9", SIGNALING, 5099, 5060, b"INVITE sip:x SIP/2.0\r\nCall-ID: a\r\n\r\n")),
        frame(linktype, ipv4_udp("10.0.0.9", media, 4000, 10004, RTP)),
        frame(linktype, ipv4_udp(media, "10.0.0.9", 10004, 4000, RTP)),
        frame(linktype, ipv4_udp("10.0.0.9", media, 4000, 10004, RTP)),
    ]


class PlannerTests(unittest.TestCase):
    def test_old_manifests_keep_their_bytes_and_filter(self):
        # The golden digests in test_softphone_runner cover the full plans;
        # here: no mediaNetworks key and the original per-destination filter.
        plan, _raw = compiled(proxy_manifest(media_networks=None, networks=["10.20.30.0/24"]))
        self.assertNotIn("mediaNetworks", plan["authorization"])
        self.assertEqual(
            plan["captureFilter"],
            "(host 10.20.30.40 and (udp port 5060 or udp portrange 10000-10020))",
        )
        validate_plan(plan)

    def test_media_networks_are_frozen_and_captured(self):
        manifest = proxy_manifest(media_networks=["10.20.41.0/30", MEDIA_POOL])
        plan, raw = compiled(manifest)
        self.assertEqual(plan["authorization"]["networks"], ["10.20.30.40/32"])
        self.assertEqual(plan["authorization"]["mediaNetworks"], [MEDIA_POOL, "10.20.41.0/30"])
        self.assertEqual(
            plan["captureFilter"],
            "(host 10.20.30.40 and (udp port 5060 or udp portrange 10000-10020))"
            " or (udp portrange 10000-10020 and (net 10.20.40.0/28 or net 10.20.41.0/30))",
        )
        self.assertTrue(any("mediaNetworks" in item for item in plan["assumptions"]))
        validate_plan(plan)
        verify_frozen_plan(plan, raw)
        self.assertEqual(capture_scope.execution_filter(plan), (plan["captureFilter"], "plan"))

    def test_a_target_inside_a_media_only_network_is_refused(self):
        manifest = proxy_manifest()
        manifest["targets"][0]["address"] = MEDIA_PEER
        with self.assertRaisesRegex(ManifestError, "outside approved networks.*mediaNetworks"):
            compiled(manifest)

    def test_breadth_rule_and_placeholders(self):
        cases = {
            "too many addresses": ["10.20.0.0/21"],
            "too many networks": [f"10.30.{index}.0/30" for index in range(17)],
            "host bits": ["10.20.40.1/28"],
            "multicast": ["224.0.1.0/30"],
            "documentation": ["198.51.100.0/27"],
            "empty": [],
            "duplicate": [MEDIA_POOL, MEDIA_POOL],
            "not a list": MEDIA_POOL,
        }
        for name, value in cases.items():
            with self.subTest(name=name), self.assertRaises(ManifestError):
                compiled(proxy_manifest(media_networks=value))

    def test_the_media_term_is_bounded(self):
        """Only UDP in the media port range, only authorized networks: never all UDP."""
        plan, _raw = compiled(proxy_manifest(networks=["10.20.30.0/24"]))
        terms = plan["captureFilter"].split(") or (")
        self.assertEqual(len(terms), 2)
        self.assertTrue(terms[0].startswith("(host 10.20.30.40 and ("))
        self.assertEqual(terms[1], "udp portrange 10000-10020 and (net 10.20.30.0/24 or net 10.20.40.0/28))")
        self.assertNotRegex(plan["captureFilter"], r"(?<!portrange )\budp\)|and udp\b|\(udp\)")

    def test_single_address_media_network_uses_host(self):
        plan, _raw = compiled(proxy_manifest(media_networks=[f"{MEDIA_PEER}/32"]))
        self.assertTrue(plan["captureFilter"].endswith(f"(udp portrange 10000-10020 and (host {MEDIA_PEER}))"))


class RuntimeValidationTests(unittest.TestCase):
    def plan(self) -> dict:
        return compiled(proxy_manifest())[0]

    def test_tampered_media_scope_is_refused(self):
        tampers = {
            "filter without the media term": lambda p: p.update(
                captureFilter=p["captureFilter"].split(" or (udp portrange")[0]),
            "filter of all UDP": lambda p: p.update(captureFilter=p["captureFilter"] + " or udp"),
            "wider media network without filter": lambda p: p["authorization"].update(
                mediaNetworks=["10.20.40.0/27"]),
            "non canonical": lambda p: p["authorization"].update(mediaNetworks=["10.20.040.0/28"]),
            "too broad": lambda p: p["authorization"].update(mediaNetworks=["10.20.0.0/16"]),
            "unsorted": lambda p: p["authorization"].update(mediaNetworks=["10.20.41.0/30", MEDIA_POOL]),
            "signaling destination in a media network only": lambda p: (
                p["resolvedDestinations"][0].update(address=MEDIA_PEER)),
        }
        for name, tamper in tampers.items():
            with self.subTest(name=name):
                plan = self.plan()
                tamper(plan)
                with self.assertRaises(PlanError):
                    validate_plan(plan)

    def test_a_legacy_plan_extends_the_capture_only_at_execution(self):
        legacy, _raw = compiled(proxy_manifest(media_networks=None, networks=[f"{SIGNALING}/32", f"{MEDIA_PEER}/32"]))
        validate_plan(legacy)
        self.assertNotIn(MEDIA_PEER, legacy["captureFilter"])
        extended, source = capture_scope.execution_filter(legacy)
        self.assertEqual(source, "plan+authorized-media")
        self.assertEqual(extended, legacy["captureFilter"] + f" or (udp portrange 10000-10020 and (host {MEDIA_PEER}))")
        # A direct-shape legacy plan (the only network is the target) runs
        # with exactly the frozen filter, as before.
        direct, _raw = compiled(proxy_manifest(media_networks=None))
        self.assertEqual(capture_scope.execution_filter(direct), (direct["captureFilter"], "plan"))


class CaptureTests(unittest.TestCase):
    MEDIA_PORTS = {"start": 10000, "end": 10020}

    def test_watchdog_counts_media_for_every_link_type_and_drains_on_stop(self):
        for linktype in (capture_scope.LINKTYPE_ETHERNET, capture_scope.LINKTYPE_LINUX_SLL2,
                         capture_scope.LINKTYPE_LINUX_SLL, capture_scope.LINKTYPE_RAW):
            with self.subTest(linktype=linktype), tempfile.TemporaryDirectory() as directory:
                capture = Path(directory) / "capture.pcap"
                capture.write_bytes(pcap(linktype, call_packets(linktype)))
                maxima = {"calls": 5, "packets": 100, "bytes": 100_000, "packetsPerSecond": 100, "callsPerSecond": 5}
                watchdog = CaptureWatchdog(capture, maxima, media_ports=self.MEDIA_PORTS, signaling_ports=[5060])
                watchdog.start()
                watchdog.stop()  # stop at once: the final pass still reads every record
                self.assertIsNone(watchdog.violation())
                self.assertEqual(watchdog.counts(), {"packets": 4, "bytes": sum(len(p) for p in call_packets(linktype)),
                                                     "calls": 1, "mediaPackets": 3})

    def test_media_alone_crosses_the_packet_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.pcap"
            capture.write_bytes(pcap(1, call_packets(1)))
            maxima = {"calls": 5, "packets": 2, "bytes": 100_000, "packetsPerSecond": 100, "callsPerSecond": 5}
            watchdog = CaptureWatchdog(capture, maxima, media_ports=self.MEDIA_PORTS, signaling_ports=[5060])
            watchdog.start()
            deadline = time.monotonic() + 2
            while watchdog.violation() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            watchdog.stop()
            self.assertEqual(watchdog.violation(), "packet_ceiling_exceeded")

    def test_payload_is_stripped_on_the_any_interface_link_types(self):
        """Regression: `--interface any` writes Linux cooked (SLL2) captures, whose
        media payload the Ethernet-only parser used to keep."""
        for linktype in (capture_scope.LINKTYPE_ETHERNET, capture_scope.LINKTYPE_LINUX_SLL2,
                         capture_scope.LINKTYPE_LINUX_SLL, capture_scope.LINKTYPE_RAW):
            with self.subTest(linktype=linktype), tempfile.TemporaryDirectory() as directory:
                capture = Path(directory) / "capture.pcap"
                capture.write_bytes(pcap(linktype, call_packets(linktype)))
                strip_media_payload(capture, self.MEDIA_PORTS, [5060])
                data = capture.read_bytes()
                self.assertNotIn(b"VOICE-PAYLOAD-CANARY", data)
                self.assertIn(b"INVITE sip:x", data)
                records, flows = capture_scope.media_flows(data, self.MEDIA_PORTS, [5060])
                self.assertEqual(records, 4)
                self.assertEqual(flows, {("10.0.0.9", MEDIA_PEER): 2, (MEDIA_PEER, "10.0.0.9"): 1})

    def test_unknown_link_type_is_refused_not_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.pcap"
            capture.write_bytes(pcap(1, call_packets(1))[:20] + struct.pack("<I", 147) + pcap(1, call_packets(1))[24:])
            with self.assertRaisesRegex(Exception, "link type 147"):
                strip_media_payload(capture, self.MEDIA_PORTS, [5060])

    def test_privacy_linter_reads_cooked_captures_and_media_networks(self):
        data = pcap(capture_scope.LINKTYPE_LINUX_SLL2, call_packets(capture_scope.LINKTYPE_LINUX_SLL2))
        addresses, complete = _classic_pcap_addresses(data)
        self.assertTrue(complete)
        self.assertEqual(addresses, {"10.0.0.9", SIGNALING, MEDIA_PEER})
        plan = compiled(proxy_manifest())[0]
        networks = {str(item) for item in _authorized_networks(plan, ["10.0.0.9/32"])}
        self.assertIn(MEDIA_POOL, networks)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plan.json").write_text(json.dumps(plan))
            (root / "capture.pcap").write_bytes(data)
            artifacts = [{"path": "capture.pcap", "size": len(data), "mediaType": "application/vnd.tcpdump.pcap"}]
            codes = [(item["code"], item["detail"]) for item in privacy_findings(root, artifacts)]
            # The assessor's own address is the only unexpected one; the
            # media peer is inside the plan's mediaNetworks.
            self.assertIn(("unexpected-network", "addresses outside expected networks: 10.0.0.9"), codes)


class ExecutionTests(unittest.TestCase):
    def run_campaign(self, manifest: dict):
        manifest = copy.deepcopy(manifest)
        manifest["targets"][0]["address"] = "127.0.0.1"
        manifest["cases"] = [manifest["cases"][1]]
        manifest["authorization"]["ceilings"]["calls"] = 1
        manifest["targets"][0].pop("credentialRef")
        manifest["authorization"]["credentialRefs"] = []
        plan, raw = compiled(manifest)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        order = root / "order.txt"
        result, run_dir = execute_campaign(
            plan,
            manifest_bytes=raw,
            run_root=root / "runs",
            runner=[sys.executable, str(TOOL), "runner", str(order)],
            capture_command=[sys.executable, str(TOOL), "capture", "{capture}", str(order), "{filter}"],
            report_command=[sys.executable, str(TOOL), "report", "{capture}"],
            preflight=lambda _destination: (True, "SIP/2.0 200 OK"),
            allow_test_runner=True,
        )
        commands = json.loads((run_dir / "commands.json").read_text())
        return result, run_dir, json.loads((run_dir / "result.json").read_text()), commands, plan

    def test_frozen_media_filter_reaches_tcpdump_and_the_result(self):
        result, _run_dir, recorded, commands, plan = self.run_campaign(
            proxy_manifest(networks=["127.0.0.1/32"]))
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(commands["capture"][-1], plan["captureFilter"])
        self.assertIn(f"net {MEDIA_POOL}", plan["captureFilter"])
        self.assertEqual(recorded["capture"]["filter"], plan["captureFilter"])
        self.assertEqual(recorded["capture"]["filterSource"], "plan")
        self.assertEqual(set(recorded["capture"]["watchdog"]), {"packets", "bytes", "calls", "mediaPackets"})

    def test_legacy_plan_capture_is_extended_with_its_authorized_media(self):
        result, _run_dir, recorded, commands, plan = self.run_campaign(
            proxy_manifest(media_networks=None, networks=["127.0.0.1/32", f"{MEDIA_PEER}/32"]))
        self.assertEqual(result.state, "succeeded")
        self.assertNotIn(MEDIA_PEER, plan["captureFilter"])
        self.assertEqual(commands["capture"][-1], plan["captureFilter"] + f" or (udp portrange 10000-10020 and (host {MEDIA_PEER}))")
        self.assertEqual(recorded["capture"]["filterSource"], "plan+authorized-media")


class RunnerTests(unittest.TestCase):
    def run_runner(self, peer: str, *, media_networks: list[str] | None = [MEDIA_POOL]):
        from test_softphone_runner import step_envelope

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        artifacts = root / "steps" / "000002"
        artifacts.mkdir(parents=True, mode=0o700)
        envelope = json.loads(step_envelope(artifacts=artifacts, password=None))
        envelope["step"]["destination"]["addresses"] = [SIGNALING]
        envelope["context"]["authorization"] = {"networks": [f"{SIGNALING}/32", "10.20.50.0/29"],
                                                "mediaPorts": {"start": 4000, "end": 4100}}
        if media_networks is not None:
            envelope["context"]["authorization"]["mediaNetworks"] = media_networks
        lines: list[str] = []
        private = root / "private"
        private.mkdir(mode=0o700)
        original = campaign_runner.DEFAULT_CALL_SECONDS
        campaign_runner.DEFAULT_CALL_SECONDS = 1
        try:
            code = campaign_runner.run(
                json.dumps(envelope).encode() + b"\n",
                pjsua=str(FAKE_PJSUA),
                environ={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                         "FAKE_PJSUA_WITNESS": str(root / "witness.json"), "FAKE_PJSUA_PEER": peer},
                emit=lines.append,
                private_root=private,
            )
        finally:
            campaign_runner.DEFAULT_CALL_SECONDS = original
        return code, json.loads(lines[0])

    def test_each_step_records_its_media_peer_and_the_admitting_authorization(self):
        for peer, rule, source, network in (
            (MEDIA_PEER, "media-network", "mediaNetworks", MEDIA_POOL),
            ("10.20.50.3", "media-network", "networks", "10.20.50.0/29"),
            (SIGNALING, "approved-address", "destination", None),
        ):
            with self.subTest(peer=peer):
                code, summary = self.run_runner(peer)
                self.assertEqual(code, 0, summary)
                self.assertEqual(summary["mediaScope"], {
                    "peer": f"{peer}:4000", "admittedBy": rule, "network": network,
                    "authorization": source, "portAdmitted": True, "inScope": True,
                })

    def test_media_scope_stop_still_fires_outside_the_authorization(self):
        code, summary = self.run_runner(OUTSIDE)
        self.assertEqual(code, 1, summary)
        self.assertIn("media_peer_outside_scope", summary["reasons"])
        self.assertEqual(summary["mediaScope"]["admittedBy"], None)
        self.assertEqual(summary["mediaScope"]["inScope"], False)
        self.assertIsNone(summary["mediaScope"]["authorization"])

    def test_a_legacy_envelope_admits_only_networks(self):
        code, summary = self.run_runner(MEDIA_PEER, media_networks=None)
        self.assertEqual(code, 1, summary)
        self.assertIn("media_peer_outside_scope", summary["reasons"])


class ScopeCompileTests(unittest.TestCase):
    def test_media_networks_are_written_media_only(self):
        from sippycup_workbench.scope_derive import _campaign_networks

        def doc(signaling, media):
            return {"signaling": {"networks": signaling}, "media": {"networks": media}}

        self.assertEqual(_campaign_networks(doc(["10.20.30.40"], ["10.20.40.0/28", "10.20.41.7"])),
                         (["10.20.30.40/32"], ["10.20.40.0/28", "10.20.41.7/32"]))
        # Media inside a signaling network adds nothing (networks admit media).
        self.assertEqual(_campaign_networks(doc(["10.20.30.0/24"], ["10.20.30.64/27"])),
                         (["10.20.30.0/24"], []))
        # Beyond the media breadth rule: merged into networks as before.
        self.assertEqual(_campaign_networks(doc(["10.20.30.40"], ["10.21.0.0/20"])),
                         (["10.20.30.40/32", "10.21.0.0/20"], []))


class ReportTests(unittest.TestCase):
    FIXTURE = ROOT / "tests" / "fixtures" / "engagement-report" / "practice"
    RUN = "20261118T025516.965852Z-local-practice-tls-0a50a448"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "engagement"
        shutil.copytree(self.FIXTURE, self.root)

    def set_media_scope(self, scope: dict, *, media_networks: list[str] | None = None) -> None:
        events = self.root / "runs" / self.RUN / "events.jsonl"
        lines = []
        for line in events.read_text().splitlines():
            event = json.loads(line)
            if event.get("event") == "step.output" and "softphone-step-result" in event.get("text", ""):
                value = json.loads(event["text"])
                value["mediaScope"] = scope
                event["text"] = json.dumps(value)
            lines.append(json.dumps(event))
        events.write_text("\n".join(lines) + "\n")
        result = self.root / "runs" / self.RUN / "result.json"
        value = json.loads(result.read_text())
        value["capture"] = {"filter": "x", "filterSource": "plan",
                            "watchdog": {"packets": 900, "bytes": 1, "calls": 1, "mediaPackets": 610}}
        result.write_text(json.dumps(value))
        if media_networks is not None:
            path = self.root / "campaign-tls.yaml"
            manifest = yaml.safe_load(path.read_text())
            manifest["authorization"]["mediaNetworks"] = media_networks
            path.write_text(yaml.safe_dump(manifest))

    def model(self):
        model, _ = build_report(self.root, Options(generated_at="2026-11-18T04:00:00Z"))
        return model

    def campaign(self, model):
        return next(item for item in model["runs"] if item["id"] == self.RUN)

    def test_campaign_media_peer_in_a_media_network_is_approved_and_shown(self):
        self.set_media_scope({"peer": "127.0.0.50:20004", "admittedBy": "media-network", "network": "127.0.0.48/28",
                              "authorization": "mediaNetworks", "portAdmitted": True, "inScope": True},
                             media_networks=["127.0.0.48/28"])
        model = self.model()
        run = self.campaign(model)
        call = next(case for case in run["details"]["cases"] if case["type"] == "call")
        self.assertEqual(
            (call["mediaPeer"], call["mediaPeerPort"], call["mediaPeerApproved"], call["mediaPeerApprovedBy"],
             call["mediaPeerRecordedRule"], call["mediaPeerAuthorization"]),
            ("127.0.0.50", 20004, True, "media-network", "media-network", "mediaNetworks"),
        )
        self.assertEqual(run["details"]["capture"]["watchdogMediaPackets"], 610)
        self.assertNotIn("media-peer-not-approved", {item["code"] for item in model["integrityExceptions"]})
        # A media network never approves a signaling target.
        self.assertIn("127.0.0.48/28", model["authorization"]["mediaOnlyNetworks"])

    def test_campaign_media_peer_outside_every_rule_is_an_integrity_exception(self):
        self.set_media_scope({"peer": "127.0.0.50:20004", "admittedBy": None, "network": None,
                              "authorization": None, "portAdmitted": True, "inScope": False})
        model = self.model()
        exceptions = [item for item in model["integrityExceptions"] if item["code"] == "media-peer-not-approved"]
        self.assertEqual(len(exceptions), 1, model["integrityExceptions"])
        self.assertIn("step 2 media peer", exceptions[0]["detail"])

    def test_rendered_report_shows_the_media_peer_and_the_watchdog(self):
        from sippycup_workbench.summary_render import render_markdown

        self.set_media_scope({"peer": "127.0.0.50:20004", "admittedBy": "media-network", "network": "127.0.0.48/28",
                              "authorization": "mediaNetworks", "portAdmitted": True, "inScope": True},
                             media_networks=["127.0.0.48/28"])
        text = render_markdown(self.model(), "0" * 64)
        self.assertIn("127.0.0.50:20004 (authorization.mediaNetworks, media only)", text)
        self.assertIn("The capture watchdog counted 900 packets against the ceilings, 610 of them media", text)


class StopObservationTests(unittest.TestCase):
    def test_campaign_media_scope_stop_is_a_safety_observation(self):
        from sippycup_workbench.summary_model import _observations

        run = {"kind": "campaign", "id": "r", "ref": "runs/r", "state": "failed", "target": None, "started": None,
               "details": {"preflight": [], "stopReason": "step_failed",
                           "cases": [{"step": 3, "reasons": ["media_peer_outside_scope"], "rtpToPeer": 4}]}}
        codes = [item["checkId"] for item in _observations(run)]
        self.assertIn("derived:media-outside-scope", codes)


class CockpitTests(unittest.TestCase):
    def test_campaign_summary_lists_media_steps_and_the_watchdog(self):
        from sippycup_cockpit import runs

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            output = {"apiVersion": "sippycup.dev/softphone-step-result/v1", "runner": "campaign-softphone-runner",
                      "mediaScope": {"peer": f"{MEDIA_PEER}:10004", "admittedBy": "media-network",
                                     "authorization": "mediaNetworks", "inScope": True, "portAdmitted": True}}
            (run / "events.jsonl").write_text(json.dumps(
                {"event": "step.output", "step": 3, "stream": "stdout", "text": json.dumps(output)}) + "\n")
            summary: dict = {}
            runs._campaign_summary(run, {"state": "succeeded", "completedSteps": 3, "exitCode": 0,
                                         "capture": {"filterSource": "plan",
                                                     "watchdog": {"packets": 700, "mediaPackets": 600}}}, summary)
            facts = dict(summary["facts"])
            self.assertEqual(facts["Capture"], "watchdog counted 700 packets, 600 of them media")
            self.assertEqual(facts["Media step 3"],
                             f"peer {MEDIA_PEER}:10004 admitted by authorization.mediaNetworks (media only)")


class LadderTests(unittest.TestCase):
    def test_campaign_media_networks_are_shown_not_redacted(self):
        from sippycup_ladder import inputs as ladder_inputs

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            plan = compiled(proxy_manifest())[0]
            (run / "plan.json").write_text(json.dumps(plan))
            (run / "capture.pcap").write_bytes(pcap(1, call_packets(1)))
            found = ladder_inputs.resolve(str(run))
            self.assertTrue(any(str(item) == MEDIA_POOL for item in found.approved), found.approved)


if __name__ == "__main__":
    unittest.main()
