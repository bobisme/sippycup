from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
LAUNCHER = ROOT / "bin" / "sippycup"
REGISTRY = ROOT / "config" / "commands.tsv"


def run_cli(*arguments: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [LAUNCHER, *arguments],
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )


def registry_rows():
    rows = []
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 7:
            raise AssertionError(f"invalid registry row: {line}")
        rows.append(fields)
    return rows


class UnifiedEntrypointContractTests(unittest.TestCase):
    def make_runtime(self, root: Path) -> Path:
        runtime = root / "runtime"
        runtime.write_text(
            # `ps` answers like an idle runtime: no other run of this checkout.
            "#!/bin/sh\n" 'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n' "printf '%s\\n' \"$@\"\n",
            encoding="utf-8",
        )
        runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
        return runtime

    def test_registry_is_complete_unique_and_targets_exist(self) -> None:
        rows = registry_rows()
        names = [row[0] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            set(names),
            {
                "help",
                "commands",
                "version",
                "go",
                "doctor",
                "mcp",
                "mcp-live",
                "webrtc",
                "web-security",
                "init",
                "rehearse",
                "one-call",
                "status",
                "scope",
                "ready",
                "stop",
                "capture",
                "preflight",
                "call",
                "checks",
                "matrix",
                "campaign",
                "media",
                "media-echo",
                "assert",
                "triage",
                "report",
                "diff",
                "ladder",
                "diagnose",
                "ui",
                "explain",
                "journal",
                "evidence",
                "pack",
                "summary",
                "torture",
                "envelope",
                "resilience",
                "chaos",
                "selftest",
                "chaos-exit-gate",
                "practice-target",
                "shell",
            },
        )
        for name, mode, host_target, container_target, *_ in rows:
            if mode in {"direct", "host", "container-private"}:
                self.assertTrue((ROOT / "bin" / host_target).is_file(), name)
            if mode == "workbench":
                self.assertEqual(container_target, "sippycup-workbench")

        public_sippycup_binaries = {
            path.name
            for path in (ROOT / "bin").glob("sippycup-*")
            if path.is_file()
        }
        registered_targets = {
            target
            for row in rows
            for target in (row[2], row[3])
            if target.startswith("sippycup-")
        }
        self.assertFalse(public_sippycup_binaries - registered_targets)
        self.assertEqual(
            registered_targets - public_sippycup_binaries,
            {"sippycup-preflight", "sippycup-selftest"},
        )

    def test_global_help_and_command_summary_need_no_runtime(self) -> None:
        missing = {"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"}
        for arguments in (
            ("--help",),
            ("help",),
            ("help", "torture"),
            ("doctor", "--help"),
            ("preflight", "--help"),
            ("selftest", "--help"),
            ("shell", "--help"),
        ):
            with self.subTest(arguments=arguments):
                result = run_cli(*arguments, env=missing)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Network activity: none", result.stdout)
        self.assertIn("torture", run_cli("--help", env=missing).stdout)

    def test_machine_registry_is_stable_and_network_free(self) -> None:
        result = run_cli(
            "commands",
            "--format",
            "json",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["apiVersion"], "sippycup.dev/commands/v1")
        self.assertFalse(value["networkActivity"])
        self.assertEqual(
            [item["name"] for item in value["commands"]],
            [row[0] for row in registry_rows()],
        )
        schema = json.loads(
            (ROOT / "schemas" / "commands-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(schema["properties"]["apiVersion"]["const"], value["apiVersion"])
        self.assertFalse(schema["properties"]["networkActivity"]["const"])
        execution = schema["properties"]["commands"]["items"]["properties"]["execution"]["enum"]
        for item in value["commands"]:
            self.assertIn(item["execution"], execution, item["name"])

    def test_version_flag_and_command_are_identical(self) -> None:
        flag = run_cli("--version")
        command = run_cli("version")
        self.assertEqual(flag.returncode, 0, flag.stderr)
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertEqual(flag.stdout, command.stdout)
        self.assertRegex(flag.stdout, r"^sippycup [0-9]+\.[0-9]+\.[0-9]+\n$")

    def test_every_public_command_has_network_free_help(self) -> None:
        missing = {"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"}
        for name, *_ in registry_rows():
            with self.subTest(name=name):
                result = run_cli(name, "--help", env=missing)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_or_duplicate_registry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            duplicate = root / "duplicate.tsv"
            duplicate.write_text(
                REGISTRY.read_text(encoding="utf-8")
                + "help|builtin|help||Getting started|offline|duplicate\n",
                encoding="utf-8",
            )
            malformed = root / "malformed.tsv"
            malformed.write_text(
                "bad/name|direct|../../bin/sh||Advanced|offline|unsafe\n",
                encoding="utf-8",
            )
            for path in (duplicate, malformed):
                with self.subTest(path=path.name):
                    result = run_cli(
                        "--help",
                        env={"SIPPYCUP_COMMAND_REGISTRY": str(path)},
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")

    def test_unknown_command_suggests_without_launching_runtime(self) -> None:
        result = run_cli(
            "tortur",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Did you mean: torture?", result.stderr)
        self.assertNotIn("No supported container runtime", result.stderr)

    def test_natural_direct_and_host_help_routes_are_network_free(self) -> None:
        missing = {"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"}
        for command in (
            "capture",
            "campaign",
            "media",
            "assert",
            "diff",
            "ladder",
            "diagnose",
            "ui",
            "evidence",
            "pack",
            "torture",
            "envelope",
            "resilience",
            "chaos",
            "report",
            "webrtc",
            "web-security",
        ):
            with self.subTest(command=command):
                result = run_cli(command, "--help", env=missing)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_webrtc_selftest_uses_fixed_optional_sandbox(self) -> None:
        for subcommand in ("self-test", "signaling-self-test", "relay-self-test"):
            with self.subTest(subcommand=subcommand):
                with tempfile.TemporaryDirectory() as root_name:
                    runtime = self.make_runtime(Path(root_name))
                    result = run_cli(
                        "webrtc",
                        subcommand,
                        "--timeout",
                        "5s",
                        env={
                            "SIPPYCUP_RUNTIME": str(runtime),
                            "SIPPYCUP_WEBRTC_IMAGE":
                                "example.invalid/sippycup-webrtc:test",
                        },
                    )
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = result.stdout.splitlines()
                for expected in (
                    "run",
                    "--rm",
                    "--network=none",
                    "--cap-drop=ALL",
                    "--read-only",
                    "--security-opt=no-new-privileges=true",
                    "--pids-limit=128",
                    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m",
                    "example.invalid/sippycup-webrtc:test",
                    subcommand,
                    "--timeout",
                    "5s",
                ):
                    self.assertIn(expected, arguments)
                self.assertNotIn("--network=host", arguments)
                self.assertNotIn("--cap-add=NET_RAW", arguments)

    def test_webrtc_ice_turn_help_needs_no_runtime(self) -> None:
        result = run_cli(
            "webrtc",
            "ice-turn",
            "--help",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Evaluate normalized ICE/STUN/TURN evidence offline", result.stdout)

    def test_webrtc_sdp_help_needs_no_runtime(self) -> None:
        result = run_cli(
            "webrtc",
            "sdp",
            "--help",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("normalized WebRTC SDP evidence offline", result.stdout)

    def test_webrtc_media_security_help_needs_no_runtime(self) -> None:
        result = run_cli(
            "webrtc",
            "media-security",
            "--help",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("DTLS-SRTP security evidence offline", result.stdout)

    def test_webrtc_call_evidence_help_needs_no_runtime(self) -> None:
        result = run_cli(
            "webrtc",
            "call-evidence",
            "--help",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("WebRTC call evidence offline", result.stdout)

    def test_container_routes_use_fixed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            environment = {
                "SIPPYCUP_RUNTIME": str(runtime),
                "SIPPYCUP_IMAGE": "example.invalid/sippycup:test",
            }
            cases = {
                "doctor": "sippycup-workbench",
                "mcp": "sippycup-mcp",
                "preflight": "sippycup-preflight",
                "selftest": "sippycup-selftest",
                "shell": "/bin/bash",
            }
            for command, target in cases.items():
                with self.subTest(command=command):
                    result = run_cli(command, "--route-probe", env=environment)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    arguments = result.stdout.splitlines()
                    self.assertIn("run", arguments)
                    self.assertIn("example.invalid/sippycup:test", arguments)
                    self.assertIn(target, arguments)
                    if command == "selftest":
                        self.assertNotIn("--network=host", arguments)
                    if command == "mcp":
                        self.assertIn("--network=none", arguments)
                        self.assertIn("--cap-drop=ALL", arguments)
                        self.assertIn("--read-only", arguments)
                        self.assertIn("--security-opt=no-new-privileges=true", arguments)
                        self.assertIn("--pids-limit=64", arguments)
                        self.assertIn("--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m", arguments)
                        self.assertTrue(
                            any(item.endswith("/work:/work:ro,Z") for item in arguments)
                        )
                        self.assertNotIn("--cap-add=NET_RAW", arguments)
                        self.assertNotIn("--cap-add=NET_BIND_SERVICE", arguments)

    def test_every_container_carries_the_checkout_and_command_labels_for_stop(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            environment = {"SIPPYCUP_RUNTIME": str(runtime)}
            for argv, command in ((("doctor",), "doctor"), (("--isolated", "--", "true"), "advanced"),
                                  (("call", "work/x.yaml", "--dial", "1"), "call")):
                with self.subTest(command=command):
                    result = run_cli(*argv, env=environment)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    arguments = result.stdout.splitlines()
                    self.assertIn(f"--label=dev.sippycup.checkout={ROOT.resolve()}", arguments)
                    self.assertIn(f"--label=dev.sippycup.command={command}", arguments)
                    self.assertLess(arguments.index(f"--label=dev.sippycup.command={command}"),
                                    arguments.index(os.environ.get("SIPPYCUP_IMAGE", "localhost/sippycup:latest")))

    def test_container_options_reuse_packaged_direct_command(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            result = run_cli(
                "--isolated",
                "--admin",
                "chaos",
                "--help",
                env={"SIPPYCUP_RUNTIME": str(runtime)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("sippycup-chaos", arguments)
        self.assertIn("--cap-add=NET_ADMIN", arguments)
        self.assertIn("--cap-add=SYS_ADMIN", arguments)
        self.assertIn("--device=/dev/net/tun", arguments)
        self.assertNotIn("--network=host", arguments)

    def test_preflight_translates_host_work_paths(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            result = run_cli(
                "preflight",
                "127.0.0.2",
                "5061",
                "tls",
                "--tls-ca",
                "work/practice/ca.crt",
                env={"SIPPYCUP_RUNTIME": str(runtime)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertEqual(
            arguments[arguments.index("--tls-ca") + 1], "/work/practice/ca.crt"
        )

    def test_container_options_translate_host_work_paths(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            result = run_cli(
                "--isolated",
                "campaign",
                "execute",
                "work/engagement/plan.json",
                "--manifest",
                str(ROOT / "work" / "engagement" / "campaign.yaml"),
                "--run-root",
                "./work/engagement/runs",
                "--interface",
                "any",
                "--note=work/not-a-separate-argument",
                "/work/already/container.json",
                "examples/outside-work.yaml",
                "work/../README.md",
                env={"SIPPYCUP_RUNTIME": str(runtime)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        tail = arguments[arguments.index("campaign") + 1 :]
        self.assertEqual(
            tail,
            [
                "execute",
                "/work/engagement/plan.json",
                "--manifest",
                "/work/engagement/campaign.yaml",
                "--run-root",
                "/work/engagement/runs",
                "--interface",
                "any",
                "--note=work/not-a-separate-argument",
                "/work/already/container.json",
                "examples/outside-work.yaml",
                "work/../README.md",
            ],
        )

    def test_call_runs_privately_with_name_only_secret_and_work_paths(self) -> None:
        canary = "launcher-secret-canary-91"
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            result = run_cli(
                "call",
                "work/engagement/profile.yaml",
                "--dial",
                "1001",
                "--username",
                "alice",
                "--secret-env",
                "SIPPYCUP_CALL_SECRET",
                "--run-root",
                "./work/engagement/calls",
                "--play",
                str(ROOT / "work" / "engagement" / "phrase.wav"),
                env={"SIPPYCUP_RUNTIME": str(runtime), "SIPPYCUP_CALL_SECRET": canary},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(canary, result.stdout)
        arguments = result.stdout.splitlines()
        self.assertNotIn("--network=host", arguments)
        self.assertNotIn("--add-host=sippycup:127.0.0.1", arguments)
        self.assertIn("--cap-add=NET_RAW", arguments)
        self.assertNotIn("--cap-add=NET_ADMIN", arguments)
        self.assertIn("--env=SIPPYCUP_NETWORK_MODE=private", arguments)
        self.assertIn("--env=SIPPYCUP_CALL_SECRET", arguments)
        self.assertEqual(
            arguments[arguments.index("sippycup-call") + 1 :],
            [
                "/work/engagement/profile.yaml",
                "--dial",
                "1001",
                "--username",
                "alice",
                "--secret-env",
                "SIPPYCUP_CALL_SECRET",
                "--run-root",
                "/work/engagement/calls",
                "--play",
                "/work/engagement/phrase.wav",
            ],
        )

    def test_call_rejects_admin_and_plans_without_a_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            for options in (("--admin",), ("--isolated", "--admin")):
                with self.subTest(options=options):
                    rejected = run_cli(
                        *options, "call", "work/p.yaml", "--dial", "1",
                        env={"SIPPYCUP_RUNTIME": str(runtime)},
                    )
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stdout, "")
                    self.assertIn("rejects --admin", rejected.stderr)
        planned = run_cli(
            "call",
            "examples/target-profile.pending.yaml",
            "--dial",
            "1001",
            "--dry-run",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(planned.returncode, 2, planned.stderr)
        self.assertIn("Guided call plan: BLOCKED", planned.stdout)
        self.assertIn("Softphone parameters:", planned.stdout)
        self.assertTrue(planned.stdout.rstrip().endswith("Network activity: none"))
        self.assertNotIn("container runtime", planned.stderr)

    def test_isolated_campaign_forwards_named_secret_variables_only(self) -> None:
        canaries = {"CAMPAIGN_SECRET": "campaign-canary-1", "OTHER_SECRET": "campaign-canary-2"}
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            result = run_cli(
                "--isolated",
                "campaign",
                "execute",
                "work/engagement/plan.json",
                "--secret-env",
                "staging-user=CAMPAIGN_SECRET",
                "--secret-env=other=OTHER_SECRET",
                env={"SIPPYCUP_RUNTIME": str(runtime), "UNNAMED_SECRET": "x", **canaries},
            )
            invalid = run_cli(
                "--isolated",
                "campaign",
                "execute",
                "work/engagement/plan.json",
                "--secret-env",
                "ref=BAD;NAME",
                env={"SIPPYCUP_RUNTIME": str(runtime)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("--env=CAMPAIGN_SECRET", arguments)
        self.assertIn("--env=OTHER_SECRET", arguments)
        self.assertFalse([item for item in arguments if "UNNAMED_SECRET" in item])
        for value in canaries.values():
            self.assertNotIn(value, result.stdout)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(invalid.stdout, "")

    def test_piped_stdin_reaches_every_container_route(self) -> None:
        # run_cli pipes stdout, so the launcher sees no terminal. A stdio MCP
        # client is in the same position and needs the container's stdin open.
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            runtime = self.make_runtime(root)
            routes = {
                "mcp": run_cli("mcp", env={"SIPPYCUP_RUNTIME": str(runtime)}),
                "escape": run_cli(
                    "--", "pjsua", env={"SIPPYCUP_RUNTIME": str(runtime)}
                ),
                "mcp-live": run_cli(
                    "mcp-live",
                    env={
                        "SIPPYCUP_RUNTIME": str(runtime),
                        "SIPPYCUP_MCP_LIVE_TRUST_ROOT": str(root),
                        "SIPPYCUP_MCP_LIVE_STATE_ROOT": str(root),
                        "SIPPYCUP_MCP_LIVE_CLIENT_ID": "test-client",
                    },
                ),
            }
        for name, result in routes.items():
            with self.subTest(route=name):
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = result.stdout.splitlines()
                self.assertIn("--interactive", arguments)
                self.assertNotIn("-it", arguments)

    def test_no_route_adds_name_entries_for_the_fixed_hostname(self) -> None:
        # sipsak was the only tool that resolved its own hostname before it
        # sent; with the in-tree OPTIONS client no route needs a hosts entry.
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            env = {"SIPPYCUP_RUNTIME": str(runtime)}
            # Plain preflight sends from the private namespace (like call);
            # only --admin keeps the host network.
            host_network = run_cli("--admin", "preflight", "192.0.2.1", env=env)
            isolated = run_cli("--isolated", "preflight", "192.0.2.1", env=env)
            plain = run_cli("preflight", "192.0.2.1", env=env)
            offline = run_cli("mcp", env=env)
        self.assertNotIn("--network=host", plain.stdout.splitlines())
        host_arguments = host_network.stdout.splitlines()
        self.assertIn("--network=host", host_arguments)
        self.assertIn("--hostname=sippycup", host_arguments)
        for result in (host_network, isolated, plain, offline):
            arguments = result.stdout.splitlines()
            self.assertFalse([item for item in arguments if item.startswith("--add-host")])
            self.assertFalse([item for item in arguments if item.endswith(":/etc/hosts:ro")])

    def make_practice_runtime(self, root: Path, inspect: str | None) -> tuple[Path, Path]:
        """A fake runtime that answers `container inspect` like a practice target."""
        hosts = root / "practice-hosts"
        hosts.write_text("127.0.0.1\tsippycup\n127.0.0.2\tsippycup-practice\n", encoding="utf-8")
        runtime = root / "practice-runtime"
        if inspect is None:
            inspect_branch = "exit 125"
        else:
            inspect_branch = f"printf '%s\\n' '{inspect.replace('HOSTS', str(hosts))}'"
        runtime.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
            'if [ "$1" = container ] && [ "$2" = inspect ]; then\n'
            f"    {inspect_branch}\n"
            "    exit 0\n"
            "fi\n"
            "printf '%s\\n' \"$@\"\n",
            encoding="utf-8",
        )
        runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
        return runtime, hosts

    def test_practice_joins_the_running_target_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime, hosts = self.make_practice_runtime(
                Path(root_name), "true|practice|none"
            )
            env = {
                "SIPPYCUP_RUNTIME": str(runtime),
                "SIPPYCUP_PRACTICE_CONTAINER": "ws-test-practice",
            }
            preflight = run_cli("--practice", "preflight", "127.0.0.2", "5060", "udp", env=env)
            escape = run_cli("--practice", "--", "pjsua", "--config-file", "/work/x.cfg", env=env)
        for result in (preflight, escape):
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = result.stdout.splitlines()
            self.assertIn("--network=container:ws-test-practice", arguments)
            self.assertFalse([item for item in arguments if "/etc/hosts" in item])
            self.assertIn("--cap-add=NET_RAW", arguments)
            self.assertIn("--interactive", arguments)
            self.assertNotIn("--network=host", arguments)
            self.assertNotIn("--add-host=sippycup:127.0.0.1", arguments)
            self.assertNotIn("--cap-add=NET_ADMIN", arguments)
        self.assertIn("sippycup-preflight", preflight.stdout.splitlines())

    def test_practice_routes_packaged_commands_and_translates_work_paths(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime, _ = self.make_practice_runtime(
                Path(root_name), "true|practice|none"
            )
            env = {
                "SIPPYCUP_RUNTIME": str(runtime),
                "SIPPYCUP_PRACTICE_CONTAINER": "sippycup-practice",
            }
            campaign = run_cli(
                "--practice", "campaign", "execute", "work/practice/plan.json",
                "--manifest", "work/practice/campaign.yaml", "--interface", "lo",
                env=env,
            )
            triage = run_cli("--practice", "triage", "work/practice/call.pcap", env=env)
        self.assertEqual(campaign.returncode, 0, campaign.stderr)
        arguments = campaign.stdout.splitlines()
        self.assertIn("--network=container:sippycup-practice", arguments)
        self.assertEqual(
            arguments[arguments.index("campaign") + 1 :],
            [
                "execute", "/work/practice/plan.json",
                "--manifest", "/work/practice/campaign.yaml", "--interface", "lo",
            ],
        )
        self.assertEqual(triage.returncode, 0, triage.stderr)
        tail = triage.stdout.splitlines()
        self.assertEqual(
            tail[tail.index("sippycup-workbench") + 1 :],
            ["triage", "/work/practice/call.pcap"],
        )

    def test_practice_fails_closed_unless_a_loopback_only_target_is_up(self) -> None:
        cases = {
            "absent": None,
            "stopped": "false|practice|none",
            "unlabelled": "true||none",
            "host-network": "true|practice|host",
            "bridge-network": "true|practice|bridge",
        }
        for name, inspect in cases.items():
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as root_name:
                    runtime, _ = self.make_practice_runtime(Path(root_name), inspect)
                    result = run_cli(
                        "--practice", "preflight", "127.0.0.2",
                        env={
                            "SIPPYCUP_RUNTIME": str(runtime),
                            "SIPPYCUP_PRACTICE_CONTAINER": "sippycup-practice",
                        },
                    )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("practice target sippycup-practice is not up", result.stderr)
                self.assertIn("practice-target up", result.stderr)

    def test_practice_rejects_conflicting_options_and_fixed_sandboxes(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime, _ = self.make_practice_runtime(
                Path(root_name), "true|practice|none"
            )
            env = {"SIPPYCUP_RUNTIME": str(runtime)}
            root = Path(root_name)
            live_env = {
                **env,
                "SIPPYCUP_MCP_LIVE_TRUST_ROOT": str(root),
                "SIPPYCUP_MCP_LIVE_STATE_ROOT": str(root),
                "SIPPYCUP_MCP_LIVE_CLIENT_ID": "test-client",
            }
            cases = {
                "admin": (("--practice", "--admin", "preflight", "127.0.0.2"), env, "cannot be combined"),
                "admin-first": (("--admin", "--practice", "shell"), env, "cannot be combined"),
                "isolated": (("--isolated", "--practice", "preflight", "127.0.0.2"), env, "cannot be combined"),
                "mcp": (("--practice", "mcp"), env, "fixed offline sandbox"),
                "mcp-live": (("--practice", "mcp-live"), live_env, "fixed least-privilege"),
                "selftest": (("--practice", "selftest"), env, "fixed isolated network"),
                "host-command": (("--practice", "report", "work/x.pcap"), env, "host-side"),
                "practice-target": (("--practice", "practice-target", "status"), env, "host-side"),
                "doctor-host": (("--practice", "doctor", "--host"), env, "doctor --host"),
            }
            for name, (arguments, environment, message) in cases.items():
                with self.subTest(case=name):
                    result = run_cli(*arguments, env=environment)
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(message, result.stderr)

    def test_mcp_rejects_privilege_broadening(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            for option in ("--isolated", "--admin"):
                with self.subTest(option=option):
                    result = run_cli(
                        option,
                        "mcp",
                        "--self-test",
                        env={"SIPPYCUP_RUNTIME": str(runtime)},
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
            self.assertIn("fixed offline sandbox", result.stderr)

    def test_mcp_live_requires_operator_roots_before_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            runtime = self.make_runtime(root)
            result = run_cli(
                "mcp-live",
                "--check-config",
                env={"SIPPYCUP_RUNTIME": str(runtime)},
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("requires SIPPYCUP_MCP_LIVE_TRUST_ROOT", result.stderr)
        self.assertNotIn(" run ", result.stderr)

    def test_mcp_live_launcher_has_fixed_least_privilege_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            runtime = self.make_runtime(root)
            trust = root / "trust"
            state = root / "state"
            trust.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            result = run_cli(
                "mcp-live",
                "--check-config",
                env={
                    "SIPPYCUP_RUNTIME": str(runtime),
                    "SIPPYCUP_MCP_LIVE_TRUST_ROOT": str(trust),
                    "SIPPYCUP_MCP_LIVE_STATE_ROOT": str(state),
                    "SIPPYCUP_MCP_LIVE_CLIENT_ID": "trusted-launcher:test",
                },
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("--network=bridge", arguments)
        self.assertIn("--cap-drop=ALL", arguments)
        self.assertIn("--read-only", arguments)
        self.assertIn("--security-opt=no-new-privileges=true", arguments)
        self.assertIn(f"--volume={trust}:/trust:ro", arguments)
        self.assertIn(f"--volume={state}:/state:rw", arguments)
        self.assertIn("sippycup-mcp-live", arguments)
        self.assertIn("--check-config", arguments)
        self.assertNotIn("--cap-add=NET_ADMIN", arguments)
        self.assertNotIn("--cap-add=NET_RAW", arguments)

    def test_mcp_live_one_call_opt_in_adds_only_raw_capture_capability(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            runtime = self.make_runtime(root)
            trust = root / "trust"
            state = root / "state"
            trust.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            result = run_cli(
                "mcp-live",
                env={
                    "SIPPYCUP_RUNTIME": str(runtime),
                    "SIPPYCUP_MCP_LIVE_TRUST_ROOT": str(trust),
                    "SIPPYCUP_MCP_LIVE_STATE_ROOT": str(state),
                    "SIPPYCUP_MCP_LIVE_CLIENT_ID": "trusted-launcher:test",
                    "SIPPYCUP_MCP_LIVE_ENABLE_ONE_CALL": "1",
                },
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("--cap-drop=ALL", arguments)
        self.assertIn("--cap-add=NET_RAW", arguments)
        self.assertNotIn("--cap-add=NET_ADMIN", arguments)

    def test_advanced_escape_hatch_preserves_argument_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            result = run_cli(
                "--",
                "printf",
                "%s",
                "two words",
                env={"SIPPYCUP_RUNTIME": str(runtime)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[-3:], ["printf", "%s", "two words"])

    def test_container_exit_status_and_signal_propagate(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            runtime = root / "runtime"
            runtime.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = ps ]; then echo "[]"; exit 0; fi\n'
                'if [ \"${SIPPYCUP_TEST_SIGNAL:-}\" = yes ]; then kill -TERM \"$$\"; fi\n'
                'exit \"${SIPPYCUP_TEST_EXIT:-0}\"\n',
                encoding="utf-8",
            )
            runtime.chmod(runtime.stat().st_mode | stat.S_IXUSR)
            failed = run_cli(
                "preflight",
                "staging.example.invalid",
                env={
                    "SIPPYCUP_RUNTIME": str(runtime),
                    "SIPPYCUP_TEST_EXIT": "23",
                },
            )
            signaled = run_cli(
                "preflight",
                "staging.example.invalid",
                env={
                    "SIPPYCUP_RUNTIME": str(runtime),
                    "SIPPYCUP_TEST_SIGNAL": "yes",
                },
            )
        self.assertEqual(failed.returncode, 23)
        self.assertEqual(signaled.returncode, -15)

    def test_host_command_rejects_container_options_before_side_effects(self) -> None:
        result = run_cli(
            "--admin",
            "capture",
            "--target",
            "192.0.2.1",
            "--dry-run",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("host-side", result.stderr)
        self.assertNotIn("Capture scope:", result.stdout)

    def test_capture_and_preflight_dry_runs_have_no_execution_side_effects(self) -> None:
        capture = run_cli(
            "capture",
            "--target",
            "192.0.2.1",
            "--output",
            "work/not-created.pcap",
            "--dry-run",
            env={"SIPPYCUP_RUNTIME": "/definitely/missing/runtime"},
        )
        self.assertEqual(capture.returncode, 0, capture.stderr)
        self.assertIn("tcpdump", capture.stdout)
        self.assertFalse((ROOT / "work" / "not-created.pcap").exists())

        preflight = subprocess.run(
            [
                ROOT / "bin" / "container-preflight",
                "staging.example.invalid",
                "5061",
                "tls",
                "--dry-run",
            ],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.assertIn("Network activity: none", preflight.stdout)
        self.assertNotIn("DNS/address resolution", preflight.stdout)

    def test_legacy_first_party_help_remains_compatible(self) -> None:
        legacy = {
            row[2]
            for row in registry_rows()
            if row[1] in {"direct", "host"} and row[2]
        }
        legacy.update({"container-preflight", "selftest", "sippycup-workbench"})
        for executable in sorted(legacy):
            with self.subTest(executable=executable):
                result = subprocess.run(
                    [ROOT / "bin" / executable, "--help"],
                    cwd=ROOT,
                    env={
                        **os.environ,
                        "SIPPYCUP_RUNTIME": "/definitely/missing/runtime",
                    },
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_docs_use_only_the_unified_first_party_entrypoint(self) -> None:
        forbidden = (
            "./bin/capture",
            "./bin/preflight",
            "./bin/report",
            "./bin/selftest",
            "./bin/campaign",
            "./bin/chaos-exit-gate",
            "./bin/sippycup-",
        )
        documents = [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]
        documents.extend((ROOT / "examples").glob("*/README.md"))
        for document in documents:
            text = document.read_text(encoding="utf-8")
            for spelling in forbidden:
                with self.subTest(document=document.name, spelling=spelling):
                    self.assertNotIn(spelling, text)

    def test_bash_completion_loads_and_reads_live_registry(self) -> None:
        completion = ROOT / "completions" / "sippycup.bash"
        syntax = subprocess.run(
            ["/bin/bash", "-n", completion],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        loaded = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f"source {completion!s}; declare -F _sippycup _sippycup_public_commands",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(loaded.returncode, 0, loaded.stderr)

    def test_every_copied_command_is_in_the_containerfile_chmod_block(self) -> None:
        text = (ROOT / "Containerfile").read_text(encoding="utf-8")
        copied = re.findall(r"(?m)^COPY bin/\S+ (/usr/local/bin/\S+)$", text)
        block = re.search(r"(?s)RUN chmod 0755 \\\n(.*?)\n\s+&& ", text)
        self.assertIsNotNone(block, "chmod 0755 block not found")
        chmodded = set(re.findall(r"/usr/\S+", block.group(1)))
        self.assertGreater(len(copied), 20)
        self.assertEqual(sorted(set(copied) - chmodded), [])

    def test_every_copied_command_source_is_executable_in_the_repository(self) -> None:
        text = (ROOT / "Containerfile").read_text(encoding="utf-8")
        for source in re.findall(r"(?m)^COPY (bin/\S+) /usr/local/bin/\S+$", text):
            with self.subTest(source=source):
                self.assertTrue(os.access(ROOT / source, os.X_OK))


if __name__ == "__main__":
    unittest.main()
