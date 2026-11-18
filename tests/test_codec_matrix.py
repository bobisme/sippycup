"""Codec control (guided call, campaign, profile) and the call matrix.

Host-only: capture, preflight, softphone, and offline analyzers are the
recording fakes from ``test_guided_call``; the matrix runs a fake executor.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

from sippycup import campaign, runtime  # noqa: E402
from sippycup_softphone import SoftphoneCall, SoftphoneError, SoftphoneResult, build_config  # noqa: E402
from sippycup_softphone import campaign_runner, driver, evidence  # noqa: E402
from sippycup_workbench import call as guided  # noqa: E402
from sippycup_workbench import matrix  # noqa: E402
from sippycup_workbench.call_explanations import CALL_EXPLANATIONS  # noqa: E402
from sippycup_workbench.profile import rehearse  # noqa: E402
from test_guided_call import NOW, SECRET, Fakes, profile_document  # noqa: E402

# PJSUA 2.17's "Cp" console listing from the prepared image (localhost/sippycup).
PJSUA_CODEC_LISTING = """List of audio codecs:
  130\tspeex/16000/1
  129\tspeex/8000/1
  128\tspeex/32000/1
  128\tiLBC/8000/1
  128\tGSM/8000/1
  128\tPCMU/8000/1
  128\tPCMA/8000/1
  128\tG722/16000/1
  128\topus/48000/2
  0\tL16/44100/2
  0\tL16/44100/1
"""


class CodecNameTests(unittest.TestCase):
    def test_supported_list_equals_the_image_binary_listing(self):
        listed = driver.parse_codec_list(PJSUA_CODEC_LISTING)
        self.assertNotIn("L16/44100", listed)  # priority 0: disabled
        entries = [{"name": item.split("/")[0], "clockRate": int(item.split("/")[1])} for item in listed]
        self.assertEqual(len(entries), 9)
        # Every enabled codec is reachable by exactly one supported name, and
        # every supported name reaches an enabled codec.
        for entry in entries:
            self.assertEqual(sum(driver.codec_matches(entry, name) for name in driver.SUPPORTED_CODECS), 1, entry)
        for name in driver.SUPPORTED_CODECS:
            self.assertTrue(any(driver.codec_matches(entry, name) for entry in entries), name)

    def test_canonical_names_are_case_insensitive_and_unknown_names_refused(self):
        self.assertEqual(driver.canonical_codec("pcma"), "PCMA")
        self.assertEqual(driver.canonical_codec("OPUS"), "opus")
        self.assertEqual(driver.canonical_codec("Speex/16000"), "speex/16000")
        for bad in ("G729", "speex", "PCMA;x", "", None, "L16/44100"):
            with self.subTest(bad=bad), self.assertRaises(SoftphoneError):
                driver.canonical_codec(bad)

    def test_exclusive_offer_disables_every_codec_then_adds_the_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            play = Path(directory) / "p.wav"
            play.write_bytes(b"")
            call = SoftphoneCall(
                destination="echo", host="192.0.2.10", port=5060, transport="udp",
                play_file=play, record_file=Path("h.wav"), duration_seconds=5,
                log_file=Path("l.log"), codecs=("PCMA", "PCMU"), exclusive_codecs=True,
            )
            lines = build_config(call).splitlines()
            start = lines.index("--dis-codec=*")
            self.assertEqual(lines[start + 1:start + 3], ["--add-codec=PCMU", "--add-codec=PCMA"])
            for codecs in (("G729",), ("pcma",), ("PCMA", "PCMA")):
                with self.subTest(codecs=codecs), self.assertRaises(SoftphoneError):
                    build_config(SoftphoneCall(**{**call.__dict__, "codecs": codecs}))


SDP_OFFER = ["v=0", "m=audio 4000 RTP/AVP 8 120", "a=rtpmap:8 PCMA/8000",
             "a=rtpmap:120 telephone-event/8000"]


class CodecFactTests(unittest.TestCase):
    def test_sdp_lists_codecs_with_static_payload_types(self):
        body = evidence.sdp(["m=audio 4000 RTP/AVP 0 9 101 13", "a=rtpmap:101 telephone-event/8000"])
        self.assertEqual(body["formats"], [0, 9, 101, 13])
        self.assertEqual(
            [(item["payloadType"], item["name"]) for item in body["codecs"]], [(0, "PCMU"), (9, "G722")]
        )

    def test_unoffered_answer_codec_is_detected(self):
        offer = evidence.sdp(SDP_OFFER)
        answer = evidence.sdp(["m=audio 5000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000"])
        facts = driver.codec_facts(("PCMA",), True, offer, answer)
        self.assertTrue(facts["offerOnlyRequested"])
        self.assertEqual([item["name"] for item in facts["unoffered"]], ["PCMU"])
        self.assertEqual(facts["negotiated"], "PCMU")
        self.assertFalse(facts["negotiatedRequested"])
        good = driver.codec_facts(("PCMA",), True, offer, evidence.sdp(SDP_OFFER))
        self.assertEqual(good["unoffered"], [])
        self.assertEqual((good["negotiated"], good["negotiatedPayloadType"]), ("PCMA", 8))

    def test_wire_report_proves_offer_and_rtp_payload_type(self):
        softphone = {"media_peer": "192.0.2.10:20000", "codecs": None, "sdp": {}}
        sdp_text = (
            "INVITE\t\taudio 4000 RTP/AVP 8 120\trtpmap:8 PCMA/8000|rtpmap:120 telephone-event/8000\n"
            "INVITE\t200\taudio 20000 RTP/AVP 8 120\trtpmap:8 PCMA/8000|rtpmap:120 telephone-event/8000\n"
        )
        rtp = "10.0.2.100\t8\n192.0.2.10\t8\n10.0.2.100\t120\n"
        report = guided.codec_report(("PCMA",), True, None, softphone, sdp_text, rtp)
        self.assertEqual(report["offered"], ["PCMA/8000"])
        self.assertTrue(report["offerOnlyRequested"])
        self.assertEqual(report["wire"]["sdpSource"], "capture")
        self.assertEqual(report["wire"]["offerFormats"], [8, 120])
        self.assertEqual(report["wire"]["rtpPayloadTypes"], {"outbound": {"8": 1, "120": 1}, "inbound": {"8": 1}})
        # telephone-event in the RTP needs the SDP's telephone-event list.
        softphone["sdp"] = {"offer": {"telephoneEvents": [120]}}
        self.assertTrue(guided.codec_report(("PCMA",), True, None, softphone, sdp_text, rtp)["wire"]["verified"])
        wrong = guided.codec_report(("PCMA",), True, None, softphone, sdp_text, "192.0.2.10\t0\n")
        self.assertFalse(wrong["wire"]["mediaUsesNegotiated"])
        self.assertFalse(wrong["wire"]["verified"])


class GuidedCodecTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.work = Path(self._directory.name) / "work"
        (self.work / "engagement").mkdir(parents=True)
        self.profile = self.work / "engagement" / "profile.yaml"
        self.write_profile(profile_document())

    def tearDown(self):
        self._directory.cleanup()

    def write_profile(self, document):
        self.profile.write_text(yaml.safe_dump(document), encoding="utf-8")

    def main(self, *arguments, fakes=None):
        fakes = fakes or Fakes()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = guided.main([str(self.profile), "--dial", "echo", "--duration", "5", *arguments],
                               fakes.dependencies(self.work))
        return code, stdout.getvalue(), stderr.getvalue(), fakes

    def test_unknown_codec_is_refused_with_exit_2_before_anything_starts(self):
        for arguments in (("--codec", "G729"), ("--codec", "PCMA,nope"), ("--codec", ","),
                          ("--codec", "PCMA", "--codec", "pcma")):
            with self.subTest(arguments=arguments):
                code, _out, err, fakes = self.main(*arguments)
                self.assertEqual(code, 2)
                self.assertIn("Nothing was started", err)
                self.assertEqual(fakes.events, [])
                self.assertFalse((self.work / "engagement" / "calls").exists())

    def test_codec_option_offers_only_the_named_codecs_in_order(self):
        code, out, _err, fakes = self.main("--codec", "pcma,PCMU", "--codec", "g722")
        self.assertEqual(code, 0, out)
        self.assertEqual(fakes.softphone_call.codecs, ("PCMA", "PCMU", "G722"))
        self.assertTrue(fakes.softphone_call.exclusive_codecs)
        (run_dir,) = sorted((self.work / "engagement" / "calls").iterdir())
        result = json.loads((run_dir / "result.json").read_text())
        self.assertEqual(result["codec"]["requested"], ["PCMA", "PCMU", "G722"])
        self.assertTrue(result["codec"]["exclusive"])
        options = json.loads((run_dir / "commands.json").read_text())["softphone_options"]
        self.assertIn("--dis-codec=*", options)

    def test_default_keeps_pcmu_preferred_and_all_codecs_offered(self):
        code, out, _err, fakes = self.main()
        self.assertEqual(code, 0, out)
        self.assertEqual(fakes.softphone_call.codecs, ("PCMU",))
        self.assertFalse(fakes.softphone_call.exclusive_codecs)

    def test_profile_approved_codecs_bound_and_default_the_offer(self):
        self.write_profile(profile_document(media={"codecs": ["PCMA", "opus"]}))
        self.assertTrue(rehearse(yaml.safe_load(self.profile.read_text()), now=NOW).ready)
        code, _out, err, fakes = self.main("--codec", "PCMU")
        self.assertEqual(code, 2)
        self.assertIn("not approved by the profile", err)
        self.assertEqual(fakes.events, [])
        code, out, _err, fakes = self.main()
        self.assertEqual(code, 0, out)
        self.assertEqual(fakes.softphone_call.codecs, ("PCMA", "opus"))
        self.assertTrue(fakes.softphone_call.exclusive_codecs)
        code, _out, _err, fakes = self.main("--codec", "OPUS")
        self.assertEqual(code, 0)
        self.assertEqual(fakes.softphone_call.codecs, ("opus",))

    def test_profile_media_section_is_validated(self):
        for media in ({"codecs": ["G729"]}, {"codecs": []}, {"codecs": ["PCMA", "pcma"]},
                      {"codecs": ["PCMA"], "extra": 1}, "PCMA"):
            with self.subTest(media=media):
                result = rehearse(profile_document(media=media), now=NOW)
                self.assertFalse(result.ready)

    def test_answer_with_unoffered_codec_is_its_own_verdict(self):
        def behave(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = result.answered = True
            result.final_status = 200
            result.rtp_tx_packets = result.rtp_rx_packets = 100
            result.codecs = driver.codec_facts(
                call.codecs, call.exclusive_codecs, evidence.sdp(SDP_OFFER),
                evidence.sdp(["m=audio 5000 RTP/AVP 0"]),
            )
            result.error = "codec_not_offered"
            return result

        code, out, _err, _fakes = self.main("--codec", "PCMA", fakes=Fakes(softphone=behave))
        self.assertEqual(code, 1)
        self.assertIn("CODEC-NOT-OFFERED", out)
        self.assertIn("PCMU (0)", out)
        self.assertIn("call.codec-not-offered", CALL_EXPLANATIONS)

    def test_488_for_an_unsupported_codec_is_media_not_acceptable(self):
        def behave(call, cancel):
            result = SoftphoneResult(destination_uri="sip:x")
            result.started = result.dialed = True
            result.final_status = 488
            result.error = "softphone_exited_unexpectedly"
            return result

        code, out, _err, _fakes = self.main("--codec", "G722", fakes=Fakes(softphone=behave))
        self.assertEqual(code, 1)
        self.assertIn("CALL-MEDIA-NOT-ACCEPTABLE", out)
        self.assertIn("The offer listed only G722", out)

    def test_schema_documents_the_codec_section_and_verdict(self):
        schema = json.loads((ROOT / "schemas" / "call-result-v1.schema.json").read_text())
        self.assertIn("codec-not-offered", schema["properties"]["verdict"]["enum"])
        self.assertIn("codec", schema["properties"])


class CampaignCodecTests(unittest.TestCase):
    def manifest(self):
        return {
            "apiVersion": "sippycup.dev/v1",
            "kind": "Campaign",
            "metadata": {"name": "codec"},
            "authorization": {
                "networks": ["10.20.30.40/32"],
                "signalingPorts": [5060],
                "mediaPorts": {"start": 10000, "end": 20000},
                "transports": ["udp"],
                "credentialRefs": ["lab"],
                "ceilings": {"calls": 2, "packets": 9000, "bytes": 9000000, "durationSeconds": 60,
                             "concurrentCalls": 1, "packetsPerSecond": 500, "callsPerSecond": 1},
                "stopConditions": {"consecutiveFailures": 1, "unexpectedResponse": True,
                                   "packetLossPercent": 5},
            },
            "targets": [{"name": "pbx", "address": "10.20.30.40",
                         "signaling": {"transport": "udp", "port": 5060}, "credentialRef": "lab",
                         "account": {"username": "alice"}}],
            "cases": [{"id": "pcma-only", "type": "call", "target": "pbx", "count": 1,
                       "dial": {"user": "echo"}, "call": {"codecs": ["pcma", "PCMU"]},
                       "budget": {"packetsPerRun": 2500, "bytesPerRun": 1200000,
                                  "durationSecondsPerRun": 15}}],
            "expectations": {"allowedSipStatuses": [100, 180, 200], "requireBidirectionalRtp": True},
            "evidence": {"capture": True, "retainPayload": False, "directory": "evidence/codec"},
        }

    def compile(self, document):
        return campaign.compile_plan(document, "0" * 64, resolver=lambda host: [])

    def test_case_codecs_are_frozen_canonical_and_revalidated(self):
        plan = self.compile(self.manifest())
        (step,) = plan["steps"]
        self.assertEqual(step["call"], {"codecs": ["PCMA", "PCMU"]})
        runtime.validate_plan(copy.deepcopy(plan))
        for bad in (["G729"], ["pcma"], [], ["PCMA", "PCMA"], "PCMA"):
            with self.subTest(bad=bad):
                broken = copy.deepcopy(plan)
                broken["steps"][0]["call"]["codecs"] = bad
                with self.assertRaises(runtime.RuntimeError):
                    runtime.validate_plan(broken)
        broken = copy.deepcopy(plan)
        broken["steps"][0]["call"]["dtmfAfterSeconds"] = 1
        with self.assertRaises(runtime.RuntimeError):
            runtime.validate_plan(broken)

    def test_manifest_codec_errors(self):
        for call in ({"codecs": ["G729"]}, {"codecs": []}, {"codecs": ["PCMA", "pcma"]},
                     {"dtmfAfterSeconds": 1, "codecs": ["PCMA"]}, {"durationSeconds": 5}):
            with self.subTest(call=call):
                document = self.manifest()
                document["cases"][0]["call"] = call
                with self.assertRaises(campaign.ManifestError):
                    self.compile(document)

    def test_runner_offers_only_the_case_codecs(self):
        plan = self.compile(self.manifest())
        step = plan["steps"][0]
        self.assertEqual(campaign_runner.call_duration(step)["effective"], 5)
        envelope = {
            "step": step,
            "context": {
                "authorization": {"mediaPorts": {"start": 10000, "end": 20000}},
                "expectations": {}, "evidence": {"retainPayload": False},
                "artifactDirectory": "/tmp/x",
            },
            "credentials": {"lab": SECRET},
        }
        parsed, _password, _context = campaign_runner.parse_envelope(json.dumps(envelope).encode())
        self.assertEqual(parsed["call"]["codecs"], ["PCMA", "PCMU"])
        envelope["step"] = {**step, "call": {"codecs": ["G729"]}}
        with self.assertRaises(campaign_runner.EnvelopeError):
            campaign_runner.parse_envelope(json.dumps(envelope).encode())


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.work = Path(self._directory.name) / "work"
        self.engagement = self.work / "engagement"
        self.engagement.mkdir(parents=True)
        self.udp = self.write("udp.yaml", profile_document(**{
            "limits.max_calls": 6, "features": {"ice": False, "turn": False, "srtp": True,
                                                "dtls_srtp": False, "webrtc": False},
            "media": {"codecs": ["PCMU", "PCMA", "G722"]}}))
        self.tcp = self.write("tcp.yaml", profile_document(**{
            "target.transport": "tcp", "limits.max_calls": 6,
            "media": {"codecs": ["PCMU", "PCMA", "G722"]}}))

    def tearDown(self):
        self._directory.cleanup()

    def write(self, name, document):
        path = self.engagement / name
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return path

    def options(self, **values):
        defaults = {"profiles": (self.udp, self.tcp), "destination": "echo",
                    "codecs": ("PCMU", "PCMA", "G722")}
        defaults.update(values)
        return matrix.MatrixOptions(**defaults)

    def plan(self, **values):
        return matrix.build_plan(self.options(**values), now=NOW, work_root=self.work)

    def test_plan_orders_cells_and_counts_calls(self):
        value = self.plan()
        self.assertTrue(value["ready"], value["blockingErrors"])
        self.assertEqual(value["totalCalls"], 6)
        self.assertEqual(
            [(cell["transport"], cell["codec"], cell["srtp"]) for cell in value["cells"]],
            [("udp", "PCMU", "off"), ("udp", "PCMA", "off"), ("udp", "G722", "off"),
             ("tcp", "PCMU", "off"), ("tcp", "PCMA", "off"), ("tcp", "G722", "off")],
        )
        self.assertEqual(value["networkActivity"], "none")
        rendered = matrix.render_human(value)
        self.assertIn("transport  srtp  PCMU     PCMA     G722", rendered)
        self.assertTrue(rendered.rstrip().endswith("Network activity: none"))

    def test_plan_refuses_what_the_profiles_do_not_approve(self):
        cases = {
            "unknown codec": {"codecs": ("G729",)},
            "codec not approved": {"codecs": ("opus",)},
            "transport not approved": {"transports": ("tls",)},
            "srtp not approved by tcp": {"srtp": ("off", "mandatory")},
            "bad srtp": {"srtp": ("maybe",)},
            "too many calls allowed": {"max_calls": 99},
            "duplicate transport": {"profiles": (self.udp, self.udp)},
        }
        for name, values in cases.items():
            with self.subTest(case=name), self.assertRaises(matrix.MatrixError):
                self.plan(**values)

    def test_plan_blocks_on_call_ceilings_and_the_profile_gate(self):
        value = self.plan(max_calls=4)
        self.assertFalse(value["ready"])
        self.assertIn("more than --max-calls 4", value["blockingErrors"][0])
        self.write("tcp.yaml", profile_document(**{"target.transport": "tcp", "limits.max_calls": 2}))
        value = self.plan()
        self.assertTrue(any("limits.max_calls 2" in item for item in value["blockingErrors"]))
        self.write("tcp.yaml", profile_document(**{"target.transport": "tcp", "limits.max_calls": 6,
                                                   "authorization.status": "pending"}))
        self.assertFalse(self.plan()["ready"])

    def fake_run(self, verdicts, progress=None, **values):
        calls = []

        def execute(options, deps):
            calls.append((options, dict(deps)))
            verdict = verdicts[len(calls) - 1]
            return (0 if verdict == "pass" else 1), {
                "verdict": verdict, "state": "completed",
                "softphone": {"final_status": 200 if verdict == "pass" else 401},
                "setup": {"inviteToAnswerSeconds": 0.042},
                "codec": {"offered": [options.codecs[0]], "negotiated": options.codecs[0],
                          "negotiatedPayloadType": 0, "wire": {"verified": True}},
                "srtp": {"active": False},
                "runDirectory": f"work/engagement/calls/run-{len(calls)}",
            }

        environ = {"PATH": "/usr/bin", "LAB_PASSWORD": SECRET}
        deps = matrix.MatrixDependencies(
            execute=execute, call_dependencies=lambda env: env, now=lambda: NOW,
            sleep=lambda seconds: None, monotonic=lambda: 0.0, environ=environ,
            work_root=self.work, install_signal_handlers=False, progress=progress,
        )
        code, value = matrix.run(self.options(**values), deps)
        return code, value, calls, environ

    def test_run_prints_one_progress_line_per_cell_start_and_end(self):
        lines = []
        code, value, calls, _environ = self.fake_run(["pass"] * 5 + ["call-media-not-acceptable"],
                                                     progress=lines.append, username="alice",
                                                     secret_env="LAB_PASSWORD")
        self.assertEqual(12, len(lines))
        self.assertTrue(lines[0].startswith("Matrix: cell 1/6 "), lines[0])
        self.assertTrue(lines[0].endswith(": calling ..."), lines[0])
        self.assertTrue(lines[-1].endswith(": call-media-not-acceptable"), lines[-1])
        self.assertNotIn(SECRET, "\n".join(lines))

    def test_run_refuses_a_username_without_a_password_source(self):
        with self.assertRaisesRegex(matrix.MatrixError, "--username needs the account password"):
            self.fake_run(["pass"] * 6, username="alice")

    def test_run_is_sequential_through_the_guided_call_and_writes_matrix_json(self):
        code, value, calls, environ = self.fake_run(["pass"] * 3 + ["pass", "pass", "call-media-not-acceptable"],
                                                     username="alice", secret_env="LAB_PASSWORD")
        self.assertEqual(code, 1)
        self.assertEqual(value["state"], "completed")
        self.assertEqual(len(calls), 6)
        for options, env in calls:
            self.assertTrue(options.exclusive_codecs)
            self.assertEqual(len(options.codecs), 1)
            self.assertEqual(env["LAB_PASSWORD"], SECRET)
        self.assertNotIn("LAB_PASSWORD", environ)
        self.assertEqual([options.profile for options, _ in calls[:3]], [self.udp] * 3)
        (directory,) = list((self.engagement / "matrix").iterdir())
        written = json.loads((directory / "matrix.json").read_text())
        self.assertNotIn(SECRET, (directory / "matrix.json").read_text())
        schema = json.loads((ROOT / "schemas" / "call-matrix-v1.schema.json").read_text())
        for key in schema["required"]:
            self.assertIn(key, written)
        self.assertIn(written["state"], schema["properties"]["state"]["enum"])
        cell_schema = schema["properties"]["cells"]["items"]
        for cell in written["cells"]:
            self.assertLessEqual(set(cell), set(cell_schema["properties"]))
            self.assertIn(cell["status"], cell_schema["properties"]["status"]["enum"])
        self.assertIn("call-media-not-acceptable", matrix.render_human(written))
        self.assertIn("pass 0.042s", matrix.render_human(written))

    def test_run_stops_on_a_stop_condition_and_does_not_hammer(self):
        code, value, calls, _environ = self.fake_run(["pass", "call-auth-failed"] + ["pass"] * 4)
        self.assertEqual(code, 3)
        self.assertEqual(len(calls), 2)
        self.assertEqual(value["state"], "stopped")
        self.assertEqual([cell["status"] for cell in value["cells"]], ["run", "run"] + ["not-run"] * 4)
        self.assertIn("call-auth-failed", value["stopReason"])
        for verdict in ("call-rate-limited", "authorization-lapsed", "registration-failed"):
            with self.subTest(verdict=verdict):
                code, _value, calls, _environ = self.fake_run([verdict] + ["pass"] * 5)
                self.assertEqual((code, len(calls)), (3, 1))

    def test_all_pass_exits_zero_and_blocked_plan_exits_two_without_calls(self):
        code, value, calls, _environ = self.fake_run(["pass"] * 6)
        self.assertEqual((code, value["passed"]), (0, 6))
        code, value, calls, _environ = self.fake_run(["pass"] * 6, max_calls=2)
        self.assertEqual((code, calls), (2, []))
        self.assertFalse((self.engagement / "matrix").exists() and any(
            "blocked" in path.read_text() for path in (self.engagement / "matrix").rglob("matrix.json")))

    def test_cli_plan_and_refusal_exit_codes(self):
        out = io.StringIO()
        deps = matrix.MatrixDependencies(now=lambda: NOW, work_root=self.work)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(matrix.main(["plan", str(self.udp), "--dial", "echo", "--codecs", "PCMU,PCMA"], deps), 0)
            self.assertEqual(matrix.main(["plan", str(self.udp), "--dial", "echo", "--codecs", "G729"], deps), 2)
            self.assertEqual(matrix.main(["run", str(self.udp), "--dial", "echo", "--codecs", "PCMU", "--dry-run"], deps), 0)
        self.assertIn("This command sent no packets.", out.getvalue())


if __name__ == "__main__":
    unittest.main()
