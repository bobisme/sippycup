from __future__ import annotations

import json
import os
from pathlib import Path
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
            "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
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
                "doctor",
                "init",
                "rehearse",
                "one-call",
                "status",
                "capture",
                "preflight",
                "campaign",
                "media",
                "media-echo",
                "assert",
                "triage",
                "report",
                "diff",
                "ui",
                "explain",
                "journal",
                "evidence",
                "pack",
                "torture",
                "envelope",
                "resilience",
                "chaos",
                "selftest",
                "chaos-exit-gate",
                "shell",
            },
        )
        for name, mode, host_target, container_target, *_ in rows:
            if mode in {"direct", "host"}:
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
            "ui",
            "evidence",
            "pack",
            "torture",
            "envelope",
            "resilience",
            "chaos",
            "report",
        ):
            with self.subTest(command=command):
                result = run_cli(command, "--help", env=missing)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_container_routes_use_fixed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            runtime = self.make_runtime(Path(root_name))
            environment = {
                "SIPPYCUP_RUNTIME": str(runtime),
                "SIPPYCUP_IMAGE": "example.invalid/sippycup:test",
            }
            cases = {
                "doctor": "sippycup-workbench",
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


if __name__ == "__main__":
    unittest.main()
