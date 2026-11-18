# Manual softphone call checklist

Use one staging account and destination approved by the Ferivox owner. Record
times in UTC and use a new PCAP for each test case.

## Information to obtain first

- Staging SIP hostname and port.
- UDP, TCP, or TLS signaling transport.
- Test username, SIP domain, and password delivery method.
- Test extension, echo service, or voice-agent destination.
- Signaling and media IP addresses or CIDRs.
- Whether RTP, SRTP, or DTLS-SRTP is expected.
- Expected codecs and DTMF method.
- Whether early media, hold, transfer, and re-INVITE are supported.
- Approved call rate, concurrent-call limit, packet-rate limit, and stop
  conditions.
- A live contact who can stop the test or inspect server metrics.

Do not place passwords in this repository, shell history, PCAP filenames, or
test notes.

## Placing the call with the guided command

For the baseline call, prefer the single guided command. It runs the scoped
capture, one OPTIONS preflight, one PJSUA call, and the offline report,
triage, and assertions in one terminal without sudo, and keeps the password
out of argv and every persisted artifact:

```sh
SIP_PASSWORD="$(your-secret-tool read staging-sip)" \
  ./bin/sippycup call work/ENGAGEMENT/profile.yaml --dial DESTINATION \
  --username USER --secret-env SIP_PASSWORD \
  --play work/ENGAGEMENT/phrase.wav
```

Use `--dry-run` first to review the plan. See `GUIDED-CALL.md`. The guided
command checks signaling, media direction, and the recording automatically;
the interactive items below (speaking, DTMF, mute, hold) still need the
manual softphone.

## Placing the call with the bundled softphone manually

The image has no sound device. PJSUA plays a prepared WAV file as the caller's
voice and records what it hears. Prepare a short mono 16-bit WAV of the agreed
phrase under `work/`, then keep every option, including the password, in a
mode-0600 file under the ignored `work/` tree so nothing secret reaches argv
or shell history:

```text
--null-audio
--add-codec PCMU
--id sip:USER@DOMAIN
--registrar sip:DOMAIN
--realm *
--username USER
--password PASSWORD
--play-file /work/ENGAGEMENT/phrase.wav
--auto-play
--rec-file /work/ENGAGEMENT/heard.wav
--auto-rec
--duration 30
--log-file /work/ENGAGEMENT/pjsua.log
```

Omit the five account lines for a service that accepts unauthenticated calls.
Start the scoped host capture in one terminal, then place the call from the
toolbox in another:

```sh
./bin/sippycup capture --target APPROVED_ADDRESS
./bin/sippycup -- pjsua --config-file /work/ENGAGEMENT/uac.cfg \
  sip:DESTINATION@DOMAIN
```

PJSUA hangs up after `--duration` seconds; type `q` and Enter to leave it.
`heard.wav` and the log may contain voice and identifiers: treat them like the
capture. Delete the configuration file when the engagement ends.

## Baseline call

- [ ] Start a target-scoped capture.
- [ ] Record the UTC start time.
- [ ] Register successfully.
- [ ] Place one call to the approved destination.
- [ ] Confirm audio from caller to destination.
- [ ] Confirm audio from destination to caller.
- [ ] Speak a recognizable phrase and note response latency.
- [ ] Test approved DTMF digits, such as `123#`.
- [ ] Mute and unmute.
- [ ] Hold and resume, if supported.
- [ ] End the call from the caller side.
- [ ] Stop the capture immediately.
- [ ] Record observed problems and UTC timestamps.

## Additional single-call cases

Use a separate capture for each case.

- [ ] Remote side ends the call.
- [ ] Caller cancels before answer.
- [ ] Destination rejects the call.
- [ ] Invalid destination.
- [ ] Incorrect password once; do not repeat without an agreed lockout test.
- [ ] One minute of silence followed by speech.
- [ ] A call long enough to cross any documented idle timeout.
- [ ] Codec or transport variant explicitly supported by the service.

## Review

- [ ] SIP setup and teardown are complete.
- [ ] RTP/SRTP is present in both directions when expected.
- [ ] Media addresses and ports match SDP.
- [ ] No media continues after call teardown.
- [ ] No unexpected third-party IP address receives signaling or media.
- [ ] Encryption matches the agreed expectation.
- [ ] Packet loss, sequence errors, and jitter are recorded.
- [ ] PCAP and notes have restricted access because they may contain audio,
  numbers, identities, network topology, or authentication material.

Generate the standard report with:

```sh
./bin/sippycup report work/CAPTURE.pcap
```
