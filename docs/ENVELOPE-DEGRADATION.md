# Conservative envelope observation and degradation

`sippycup.envelope_analysis` fuses observations at the exact levels in a
frozen envelope plan. It accepts SIPp success/setup/timeout/5xx values, packet
oracle assertion verdicts, RTP loss/jitter, socket error counts, and an
optional read-only health adapter. No observation opens a network socket.

Every metric is typed as `known`, `missing`, or `stale` and retains its source.
Required missing or stale data causes an `unknown` stop decision; it is never
converted to zero or healthy. Optional telemetry may be absent, but its fact
remains explicitly missing in the cited sample.

## Policy and decisions

Each configured metric declares:

- `direction`: whether higher (`max`) or lower (`min`) is adverse;
- `soft` and stronger `hard` thresholds;
- `consecutive`: at least two adverse samples required for backoff;
- `changeDelta`: adverse movement from the median of the fixed baseline
  samples;
- `required`: whether missing/stale data stops the run.

A hard threshold stops immediately. A soft or change-point breach first
becomes `suspect`; only the configured consecutive streak becomes
`degraded`/`backoff`. A clear intervening sample resets the streak, providing
hysteresis against noise. Every decision embeds the exact fact, rule,
baseline, and streak used.

The output reports only a tested interval:

- `lowerTestedHealthy` is the last tested level with clear evidence;
- `upperTestedDegraded` is the first tested level whose repeated or hard
  evidence triggered;
- a healthy trace that ends first is `censoredByTestedCeiling`.

`capacityClaim` is always null. The detector never interpolates a midpoint,
promotes an untested plan level, or calls an authorization ceiling capacity.

## Health adapter boundary

`run_health_adapter` executes an argv array without a shell, closes stdin,
enforces a caller-supplied deadline from 1 through 60,000 ms, requires bounded
JSON shaped as `{"value": number, "observedAtMs": integer}`, and limits
accepted output to 64 KiB. Timeout, failure, malformed/non-finite output, and
oversize output become typed missing observations. Fusion applies
`staleAfterMs` against the sample clock.

Run the seeded stable, gradual, abrupt, hysteretic, noisy, change-point,
unknown-data, and censored synthetic traces with:

```sh
make envelope-analysis-test
```
