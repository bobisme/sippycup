# Envelope backoff and recovery

`prove_recovery` stops admission for degradation, SIGINT, or adapter failure,
bounds teardown by the immutable global deadline, waits the authorized
cooldown, then schedules periodic one-call/media canaries through the recovery
deadline. Baseline and recovery canaries must carry byte-equivalent reviewed
expectations.

Reports distinguish `recovered_after_load_failure`, `failed_to_recover`,
`recovered_after_stop`, and `recovery_unproven`. They preserve the tested knee
interval, trigger, policy, hysteresis decisions, recovery time, deadlines, and
per-level capture/assertion links. Authorization-censored runs remain censored
and `capacityClaim` is always null.
