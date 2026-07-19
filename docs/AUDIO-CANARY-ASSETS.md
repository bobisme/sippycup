# Audio canary assets

`media/canary-v1` is the deterministic source corpus for media send/analyze
workflows. It contains raw RTP-ready PCMU, PCMA, and G.722 payloads for both
call directions. The files are generated from integer-only synthesis in
`lib/sippycup_media/canary.py`; no recorded or third-party audio is used.

Each payload lasts one second and divides into fifty 20 ms packets:

| Codec | Media sample rate | RTP clock | Bytes per packet |
|---|---:|---:|---:|
| PCMU | 8 kHz | 8 kHz | 160 |
| PCMA | 8 kHz | 8 kHz | 160 |
| G.722 | 16 kHz | 8 kHz | 160 |

The first 420 ms carries three seeded marker chirps. Caller-to-callee markers
sweep upward and use `c2s-*` IDs; callee-to-caller markers sweep downward and
use `s2c-*` IDs. The distinct sweep codes and seeded frequency sets prevent a
returned direction from being mistaken for the sent direction.

The remainder contains an exact-zero calibrated silence window and tone steps
at -24, -18, and -12 dBFS. After codec decoding, silence passes when every
sample is at most 104 signed 16-bit PCM units in magnitude (approximately
-50 dBFS). A sample magnitude of 32760 or greater is clipping. Marker recovery
requires normalized correlation of 0.80 and permits position error of one
20 ms packet.

Rebuild or verify the checked-in files with:

```sh
make media-canary
make media-canary-check
```

The manifest records codec rates, RTP clock rates, packetization, marker
positions, levels, thresholds, and SHA-256 hashes. Generated payloads and
metadata are CC0-1.0; the synthetic-speech option is deliberately absent from
v1 so the fixture has no speech licensing or privacy ambiguity.
