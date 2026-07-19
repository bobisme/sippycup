"""Deterministic dashboard presenter and text/Urwid renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Mapping

from .state import Event, ViewState

MIN_WIDTH = 100
MIN_HEIGHT = 30


@dataclass(frozen=True)
class Metric:
    value: str = "unknown"
    status: str = "unknown"

    def __post_init__(self):
        if self.status not in {"good", "warning", "unknown", "stale"}:
            raise ValueError("metric status must be good, warning, unknown, or stale")

    def render(self) -> str:
        token = {
            "good": "[OK]",
            "warning": "[WARN]",
            "unknown": "[? UNKNOWN]",
            "stale": "[~ STALE]",
        }[self.status]
        return f"{token} {self.value}"


@dataclass(frozen=True)
class WarningLink:
    message: str
    evidence: str


@dataclass(frozen=True)
class DashboardModel:
    authorization: str = "not loaded"
    planned_cases: int = 0
    current_step: str = "none"
    next_step: str = "none"
    utc_started: str = "not started"
    utc_elapsed: str = "00:00:00"
    budgets: Mapping[str, Metric] = field(default_factory=dict)
    capture: Metric = Metric()
    capture_path: str = "not assigned"
    report_path: str = "not generated"
    sip_ladder: tuple[str, ...] = ()
    sip_counters: Mapping[str, Metric] = field(default_factory=dict)
    media: Mapping[str, Metric] = field(default_factory=dict)
    rtp: Mapping[str, Metric] = field(default_factory=dict)
    assertions: Mapping[str, Metric] = field(default_factory=dict)
    recovery: Metric = Metric()
    warnings: tuple[WarningLink, ...] = ()
    first_run: bool = True

    def as_json_record(self, state: ViewState) -> dict[str, object]:
        return {
            "schema": "sippycup.dashboard/v1",
            "phase": state.phase,
            "actions": list(state.actions),
            "model": _jsonable(asdict(self)),
        }


def apply_dashboard_event(model: DashboardModel, event: Event) -> DashboardModel:
    """Update presentation data only; protocol verdicts remain producer-owned."""
    payload = event.payload
    updates = {}
    scalar = {
        "authorization": "authorization",
        "plannedCases": "planned_cases",
        "currentStep": "current_step",
        "nextStep": "next_step",
        "utcStarted": "utc_started",
        "utcElapsed": "utc_elapsed",
        "capturePath": "capture_path",
        "reportPath": "report_path",
    }
    for source, destination in scalar.items():
        if source in payload:
            updates[destination] = payload[source]
    metric_groups = {
        "budgets": "budgets",
        "sipCounters": "sip_counters",
        "media": "media",
        "rtp": "rtp",
        "assertions": "assertions",
    }
    for source, destination in metric_groups.items():
        value = payload.get(source)
        if isinstance(value, dict):
            updates[destination] = {
                str(name): _metric(metric) for name, metric in value.items()
            }
    if "capture" in payload:
        updates["capture"] = _metric(payload["capture"])
    if "recovery" in payload:
        updates["recovery"] = _metric(payload["recovery"])
    if isinstance(payload.get("sipLadder"), list):
        updates["sip_ladder"] = tuple(str(item) for item in payload["sipLadder"][:100])
    if event.kind == "run.started":
        updates["first_run"] = False
    if event.kind == "run.warning":
        link = WarningLink(
            str(payload.get("message", "runtime warning")),
            str(payload.get("evidence", "events.jsonl")),
        )
        updates["warnings"] = (model.warnings + (link,))[-100:]
    return replace(model, **updates)


def render_text(
    model: DashboardModel,
    state: ViewState,
    *,
    width: int = MIN_WIDTH,
    height: int = MIN_HEIGHT,
    help_overlay: bool = False,
) -> str:
    if width < 40 or height < 10:
        raise ValueError("terminal must be at least 40x10")
    if help_overlay:
        lines = [
            "SIPPYCUP HELP (?)",
            "s start  p pause-new-calls  x graceful-stop  ! emergency-stop  k skip",
            "n note  b bookmark  t Termshark  ? help  q quit",
            "Actions unavailable in the current phase remain visible but disabled.",
            "Traffic begins only after the frozen plan is reviewed and Start is pressed.",
        ]
        return _fit(lines, width, height)

    compact = width < MIN_WIDTH or height < MIN_HEIGHT
    lines = [
        f"SIPPYCUP MISSION CONTROL  phase={state.phase.upper()}  actions={','.join(state.actions)}",
        f"AUTHORIZATION  {model.authorization}",
        f"PLAN  cases={model.planned_cases}  current={model.current_step}  next={model.next_step}",
        f"UTC  started={model.utc_started}  elapsed={model.utc_elapsed}",
        f"CAPTURE  {model.capture.render()}  path={model.capture_path}",
        f"REPORT  path={model.report_path}",
    ]
    if model.first_run:
        lines += [
            "FIRST RUN: no traffic starts during planning; review scope/budgets, then press s.",
            "Artifacts, events, capture, reports, and assertions are written under the run directory.",
        ]
    lines += _metric_line("BUDGETS", model.budgets)
    if compact:
        lines += _metric_line("SIP", model.sip_counters)
        lines += _metric_line("RTP", model.rtp)
        lines += _metric_line("ASSERT", model.assertions)
        lines.append(f"RECOVERY  {model.recovery.render()}")
    else:
        lines += ["", "SIP LADDER"]
        lines += [f"  {entry}" for entry in model.sip_ladder[-6:]] or ["  [? UNKNOWN] no dialog events"]
        lines += _metric_line("SIP COUNTERS", model.sip_counters)
        lines += ["", "NEGOTIATED MEDIA"] + _metric_line("MEDIA", model.media)
        lines += _metric_line("RTP BY DIRECTION", model.rtp)
        lines += ["", "ASSERTIONS"] + _metric_line("VERDICTS", model.assertions)
        lines.append(f"RECOVERY CANARY  {model.recovery.render()}")
    if model.warnings:
        lines += ["", "WARNINGS"]
        lines += [f"[WARN] {item.message} -> {item.evidence}" for item in model.warnings[-4:]]
    lines.append("Press ? for help. Status always includes text; color is supplementary.")
    return _fit(lines, width, height)


def urwid_widget(model: DashboardModel, state: ViewState, *, width: int = MIN_WIDTH):
    """Build an Urwid widget without coupling state or protocol code to Urwid."""
    import urwid

    text = render_text(model, state, width=width, height=1000)
    return urwid.Filler(urwid.Padding(urwid.Text(text), left=1, right=1), valign="top")


def _metric(value: object) -> Metric:
    if isinstance(value, Metric):
        return value
    if isinstance(value, dict):
        return Metric(str(value.get("value", "unknown")), str(value.get("status", "unknown")))
    return Metric(str(value), "unknown")


def _metric_line(title: str, metrics: Mapping[str, Metric]) -> list[str]:
    if not metrics:
        return [f"{title}  [? UNKNOWN] no metrics"]
    return [title + "  " + "  ".join(f"{name}={metric.render()}" for name, metric in metrics.items())]


def _fit(lines: list[str], width: int, height: int) -> str:
    fitted = []
    for line in lines[:height]:
        fitted.append(line if len(line) <= width else line[: max(0, width - 1)] + "…")
    return "\n".join(fitted)


def _jsonable(value):
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return value
