# Capacity envelope exit gate

`make envelope-exit-gate` replays deterministic synthetic healthy, gradual,
abrupt, stale-adapter, SIGINT, slow-recovery, and never-recovery traces. The
owner-reviewable default policy is `config/envelope-policy.json`; deployment
requires explicit owner approval.

The reference envelope reaches CPS 8 only while healthy. Gradual evidence
backs off at tested level 4, abrupt/unknown health stops on its first sample,
and recovery canaries run every 20 seconds. Teardown, cooldown, and recovery
remain clamped to the 600-second global authorization. Every tested level maps
to a capture and assertion artifact. Reports keep `capacityClaim` null and
publish only tested knee bounds or an authorization-censored result.
