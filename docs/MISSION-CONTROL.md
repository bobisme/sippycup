# Mission-control architecture

Mission control consumes structured campaign and assertion events through
explicit adapters. It never parses terminal colors, cursor movements, or other
ANSI tool output. Producers emit the versioned `sippycup.ui-event/v1`
envelope; protocol parsing and verdict logic remain in the campaign and oracle
libraries.

The shared pure reducer defines planning, ready, running, warning, stopping,
recovery, complete, and failed phases. Interactive and noninteractive views
both render the resulting `sippycup.view-state/v1` record, including the same
available actions. Per-source sequence tracking exposes late events. Schema
errors become visible warnings. The producer bridge has a finite queue,
backpressure, and explicit drop telemetry rather than unbounded memory growth.
Replaying the checked-in JSONL fixture is deterministic.

The interactive renderer uses Urwid 4.0.4, pinned in the image. Urwid is a
console-focused library with maintained asyncio/select event-loop support; the
state and protocol layers do not import it. This keeps headless JSON operation
usable when no TTY exists and makes rendering replaceable without changing
test semantics.

```text
campaign JSONL ─┐
oracle result ──┼─> explicit adapters -> bounded queue -> pure reducer
operator input ─┘                                  ├-> Urwid view
                                                   └-> JSON view
```

The documented full dashboard minimum is 100x30. Between 40x10 and that size,
the renderer switches to a compact summary and truncates with an ellipsis
without wrapping beyond the terminal. Status uses explicit `[OK]`, `[WARN]`,
`[? UNKNOWN]`, and `[~ STALE]` labels; color is supplementary. Press `?` for a
one-key action overlay.

Controls are dispatched through a narrow campaign-control API, never from
rendering functions. Start, emergency stop, and skip require a fresh
confirmation; repeated idempotency keys cannot apply an action twice. Graceful
stop remains available in every phase. Notes and bookmarks append to a private
`notes.jsonl` metadata file for later evidence packaging. Termshark receives a
fixed argv and a new process session, then returns to the unchanged mission
state without inheriting campaign supervision.
