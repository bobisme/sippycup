"""Every user-facing explanation of the cockpit, in one reviewable module.

Each stage paragraph is condensed from the documents named in ``source`` so
an operator under time pressure does not have to open them. Keep wording
here, not scattered through the renderers, so it can be tested and reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StageText:
    identifier: str
    number: int
    title: str
    what_and_why: str
    source: str


STAGES: tuple[StageText, ...] = (
    StageText(
        "prepare",
        1,
        "Prepare",
        "Create the private engagement record and make sure the toolbox image "
        "is built from the current checkout. The engagement directory under "
        "work/ holds the journal, scope, profile, and every run, so evidence "
        "and reasoning stay together. `doctor` inspects the image without any "
        "network activity; a stale image means live commands would run older "
        "code than the one you reviewed.",
        "docs/ASSESSMENT-WORKFLOW.md (Preparation), docs/CLI.md",
    ),
    StageText(
        "practice",
        2,
        "Practice",
        "Rehearse the whole live sequence against the local practice target "
        "first: a real Asterisk on 127.0.0.2 inside a loopback-only network "
        "namespace, so no packet can leave the host. One passing guided call "
        "against it proves the image, capture, registration, media, and "
        "evidence path work before you touch the owner's system. Recommended "
        "before the first live call; it does not block the later stages.",
        "docs/PRACTICE-TARGET.md",
    ),
    StageText(
        "scope",
        3,
        "Scope",
        "Record the service owner's written answers once in the private "
        "scope.yaml: `scope init`, send the `scope questions` sheet, fill the "
        "file from the written reply, `scope check` until it is complete and "
        "consistent, then `scope compile` to generate the target profile, "
        "campaign manifest, and oracle expectations. The file holds credential "
        "reference names only, never a password.",
        "docs/SCOPE-INTAKE.md",
    ),
    StageText(
        "rehearse",
        4,
        "Rehearse",
        "Rehearsal checks the compiled target profile against the clock with "
        "no network traffic: approval present, inside its validity window, "
        "and the target a literal approved address. The one-call plan shows "
        "the exact capture, preflight, and analysis commands. Nothing sends "
        "traffic unless this stage is ready.",
        "docs/ASSESSMENT-WORKFLOW.md (Network-free rehearsal)",
    ),
    StageText(
        "first-call",
        5,
        "First call",
        "Place one guided baseline call: scoped capture, one OPTIONS "
        "preflight, one call with media, then offline report, triage, and "
        "oracle assertions, all in one command. Review the dry run first; it "
        "prints the plan and sends nothing. The live call re-checks the "
        "approval before the first packet and before the call.",
        "docs/GUIDED-CALL.md",
    ),
    StageText(
        "campaign",
        6,
        "Campaign",
        "A campaign runs the compiled manifest's cases under a supervisor "
        "that enforces every ceiling and stop condition from the live "
        "capture. `campaign plan` freezes the reviewed plan without traffic; "
        "`campaign run` executes exactly that plan and refuses one that no "
        "longer matches the manifest.",
        "docs/CAMPAIGN-MANIFEST.md",
    ),
    StageText(
        "checks",
        7,
        "Security checks",
        "The owner-approved posture checks: banners, TLS, cleartext "
        "signaling, unauthenticated REGISTER and INVITE, Digest quality, the "
        "account-existence differential, and nonce replay. Each check has a "
        "declared request bound and runs only when the profile's "
        "security_checks.approved list names it; `checks plan` shows exactly "
        "what would be sent. A completed run writes findings.json; a finding "
        "is a candidate to confirm, not a failed run. The stage is shown as "
        "not applicable when the scope approves no checks.",
        "docs/SECURITY-CHECKS.md",
    ),
    StageText(
        "evidence",
        8,
        "Evidence",
        "Every run needs an evidence manifest (hashes, sensitivity, privacy "
        "findings) and a journal entry that links it; the guided call writes "
        "its manifest and prints the journal command. Lint privacy before "
        "sharing anything, and pack a run into a verifiable archive only "
        "after the privacy and disclosure decisions are made.",
        "docs/ASSESSMENT-WORKFLOW.md, docs/EVIDENCE-PRIVACY.md, docs/EVIDENCE-PACKS.md",
    ),
    StageText(
        "report",
        9,
        "Owner report",
        "Write the owner report with `summary`: what was approved, what ran, "
        "what happened, what was found, and what to fix. It re-checks every "
        "run against the approved targets, window, and ceilings and lists any "
        "integrity exception first; pass --forbid-file with the account "
        "password file so the report fails closed if the password appears. "
        "The stage is done when a report covers every run and has no "
        "integrity exception. An internal draft from the journal is optional.",
        "docs/ENGAGEMENT-REPORT.md, docs/ASSESSMENT-WORKFLOW.md",
    ),
)

STAGE_BY_ID = {stage.identifier: stage for stage in STAGES}

KEYS: tuple[tuple[str, str], ...] = (
    ("Up/Down, j/k", "move the selection"),
    ("Tab", "switch between Actions and Runs"),
    ("Enter", "open the selected action (confirmation first) or run"),
    ("1-9", "show what and why for that stage"),
    ("r", "refresh the dashboard from disk"),
    ("S", "skip (or un-skip) the recommended practice stage"),
    ("?", "show or hide this help"),
    ("q", "quit (Esc closes a panel)"),
)

LINE_KEYS: tuple[tuple[str, str], ...] = (
    ("N", "open action N (shows the confirmation panel first)"),
    ("rN", "browse run N"),
    ("sN", "show what and why for stage N"),
    ("skip", "skip (or un-skip) the recommended practice stage"),
    ("Enter", "refresh the dashboard"),
    ("?", "show this help"),
    ("q", "quit"),
)

MARKERS: tuple[tuple[str, str], ...] = (
    ("[ok]", "done or healthy"),
    ("[>>]", "current stage"),
    ("[  ]", "not done yet"),
    ("[--]", "recommended, not required; or not applicable"),
    ("[!!]", "blocked, expired, stale, or failed"),
    ("[??]", "unknown or unreadable"),
    ("[LIVE]", "sends traffic to a target; typed confirmation required"),
    ("[local]", "starts or builds a local container; no target traffic"),
    ("[offline]", "network-free"),
)

LIVE_CONFIRMATION = (
    "This action sends traffic. Type the last 4 characters of the approval "
    "id ({approval_hint}) to start it, or press Enter to cancel."
)
SECRET_GUIDANCE = (
    "The cockpit never takes a password as typed text. Give either a "
    "password file beneath work/ that only you can read (mode 0600), or the "
    "name of an environment variable that is already set. To create a file "
    "safely without the password reaching shell history:\n"
    "  (umask 077; IFS= read -rs P; printf '%s' \"$P\" > {path}; unset P)\n"
    "then check it: ls -l {path}  (expect -rw-------)"
)
JOURNAL_NOTE_PRIVACY = (
    "The note is passed to `journal add` on standard input (--summary-file -), "
    "so it does not appear in the process list. Never record passwords, "
    "tokens, or decoded voice."
)
NO_ENGAGEMENT = (
    "No engagement directory with engagement.json was found under work/. "
    "Create one: journal init creates the private record, then scope init "
    "creates the pending scope file."
)


def stage_help(identifier: str) -> str:
    stage = STAGE_BY_ID[identifier]
    return f"Stage {stage.number}: {stage.title}\n\n{stage.what_and_why}\n\nSource: {stage.source}"


def keys_help(*, line_mode: bool = False) -> str:
    rows = LINE_KEYS if line_mode else KEYS
    width = max(len(key) for key, _ in rows)
    lines = ["Keys:"]
    lines.extend(f"  {key.ljust(width)}  {meaning}" for key, meaning in rows)
    lines.append("")
    lines.append("Markers (colour is only a supplement):")
    marker_width = max(len(key) for key, _ in MARKERS)
    lines.extend(f"  {key.ljust(marker_width)}  {meaning}" for key, meaning in MARKERS)
    return "\n".join(lines)
