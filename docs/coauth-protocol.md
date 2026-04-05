# core-keys co-authorization protocol — v1 (frozen 2026-08-28)

Status: FROZEN for M2 implementation. Decisions D1–D4 settled with the owner:
- **D1**: co-authorization is an authenticated in-session Noise message; the
  daemon never produces a detached signature over the to-be-signed bytes.
- **D2**: separate keys — an X25519 Noise static (ECDH-only handle) distinct from
  any Ed25519 identity/credential key.
- **D3**: ship C (co-authorization) first; freeze architecture-B (at-rest store
  wrapping) interface points now, implement later.
- **D4**: implement SSH (daemon-initiated) co-auth first, FIDO2 second.

Companion: the reviewed proposal artifact and DESIGN.md. This document is the
implementation source of truth; on any conflict, this wins for the protocol.

## 0. The invariant

The device signs a credential ONLY when it has an authenticated request from the
paired desktop, over the EXACT bytes to be signed, AND the user presses the
button after reading honest context on the device's display.

## 1. Principals, transports, keys

- Device **D**: composite USB device. TLC-1 = standard CTAP2 authenticator
  (usage page 0xF1D0, browser-facing). TLC-2 = vendor channel (usage page
  0xFF00), openable by any unprivileged local process.
- Desktop daemon **H**: also the ssh-agent. Talks to D over TLC-2.
- Keys (D2 = separate):
  - `D_s` / `H_s`: **X25519** static keypairs = the Noise statics. ECDH-only
    handle (SE050 on product / MCU flash on mule; TPM/Secure Enclave on desktop).
    No `sign()` is ever reachable on these.
  - Credential keys, device-held: SSH `ssh-ed25519`; FIDO2 P-256/ES256 (later).
  - Optional Ed25519 identity: NOT used in v1 (D1 removes the need). Reserved.
- Peers are pinned and matched by the exact 32-byte X25519 static.

### 1.1 Key validation (run at pairing AND every handshake)
- Reject low-order / small-subgroup X25519 points (the RFC 7748 blacklist).
- Reject an all-zero X25519 DH output on every DH.
- Reject non-canonical 32-byte encodings (high bit / reduction as applicable).

## 2. Constants

```
CKVP_MAX_MSG        = 2048      # bytes; START total-length cap. Reject larger.
CKVP_REASM_TIMEOUT  = 250 ms    # half-open reassembly discarded after this
PAIR_NONCE_LEN      = 16        # bytes (128-bit) for H_nonce and D_nonce
SAS_DIGITS          = 6         # 000000..999999 (~2^20 space, ~2^-20 per online attempt)
NOISE_PATTERN       = Noise_KK_25519_ChaChaPoly_SHA256
REQ_ID_LEN          = 8         # bytes; per-operation id
DEDUP_WINDOW        = 32        # recent request_ids kept for replay dedup
COAUTH_DEADLINE     = 12 s      # device: max wait for daemon approval
BUTTON_WINDOW       = 20 s      # device: max wait for the button after approval
KEEPALIVE_CADENCE   = 80 ms     # CTAPHID keepalive while awaiting (FIDO2, later)
MAX_PENDING_HS      = 2         # concurrent half-open Noise handshakes
MAX_AUTH_DAEMONS    = 8         # authorized-daemon list cap on the device

# Domain-separation labels (ASCII, no trailing NUL)
L_COMMIT = "core-keys/pair/v1/commit"
L_SAS    = "core-keys/pair/v1/sas"
```

Rationale for COAUTH_DEADLINE + BUTTON_WINDOW: their sum (32 s) must fit inside
the tightest common WebAuthn budget once FIDO2 lands; Firefox's default clamp is
~30 s, so for the FIDO2 path these tighten (see §7). SSH has no such clamp
(`LoginGraceTime` default 120 s), so the SSH path uses the values above.

## 3. CKVP framing (vendor channel, TLC-2)

64-byte HID reports. Every logical message carries a channel id (`chan`, u16) so
the device demultiplexes concurrent senders and isolates reassembly.

```
START report:  byte0      = 0x80 | msg_type   (msg_type in 0x00..0x3F)
               byte1..2   = chan (BE u16)
               byte3..4   = total payload length (BE u16, <= CKVP_MAX_MSG)
               byte5..63  = first 59 payload bytes
CONT report:   byte0      = seq (0x00..0x7F, wraps; high bit clear)
               byte1..2   = chan (BE u16)
               byte3..63  = next 61 payload bytes
```

- `chan` is chosen by the sender (host side allocates; device echoes). The device
  keeps at most one reassembly slot per active `chan`, bounded by MAX_PENDING_HS
  during handshake and 1 established session otherwise.
- A START declaring length > CKVP_MAX_MSG is dropped (rate-limited).
- Never pre-allocate the declared length; append per CONT into a fixed buffer.
- Reassembly older than CKVP_REASM_TIMEOUT is discarded.
- Unparseable frames are rate-limited, dropped events — never session-fatal.

### 3.1 Message types (`msg_type`)
```
0x01 PAIR_INIT      (H->D, plaintext)   commitment + machine_name
0x02 PAIR_RESP      (D->H, plaintext)   D_pub + D_nonce
0x03 PAIR_OPEN      (H->D, plaintext)   H_pub + H_nonce (reveal)
0x04 PAIR_CONFIRM   (D->H, plaintext)   ack after button (carries no authority)
0x10 NOISE_HS       (both, plaintext)   a Noise handshake message
0x11 NOISE_MSG      (both)              a Noise transport message (encrypted)
```
No other plaintext msg_type exists. **No plaintext frame may change device
state.** (The M1 mule's reboot/status/loopback CONTROL path is removed from any
shipping image; see §11.) All application records travel inside NOISE_MSG.

## 4. Pairing (once per (device, machine))

Preconditions: the user physically arms enroll mode on D (long-press, or
boot-into-pairing). D reveals NO key material and shows nothing until armed; a
PAIR_INIT received while not armed is dropped silently.

```
0.  User arms ENROLL on D (physical gesture).
1.  H picks H_nonce (PAIR_NONCE_LEN random). H -> D  PAIR_INIT {
        c = SHA-256(L_COMMIT || H_pub || H_nonce || machine_name),
        machine_name }
2.  D picks D_nonce (PAIR_NONCE_LEN random). D -> H  PAIR_RESP { D_pub, D_nonce }
3.  H -> D  PAIR_OPEN { H_pub, H_nonce }
4.  D recomputes c over the revealed (H_pub, H_nonce, machine_name);
        ABORT on mismatch.
5.  Both compute
        SAS = SHA-256(L_SAS || D_pub || H_pub || D_nonce || H_nonce
              || machine_name)  reduced to 6 decimal digits (first 8 bytes
              big-endian, mod 10^6).
6.  D shows SAS + machine_name(unverified) on a DISTINCT enroll screen; H shows
        the same SAS in the daemon UI. User compares; on match presses D's button.
7.  Proof-of-possession: run the Noise_KK handshake (§5) immediately.
        Pin the peer static ONLY if the handshake completes:
        D stores H_pub in its authorized list; H stores D_pub.
        PAIR_CONFIRM is an ack only and confers no authority.
```

- **SAS**: 6 decimal digits (~2^20 space). Commit-reveal makes forgery
  online-only at ~2^-20 per attempt; pairing is rare and button-gated.
  Rate-limit pairing attempts.
- **Adding an Nth desktop (list non-empty)**: in addition to gesture + button,
  require an EXISTING authorized daemon's in-session (Noise) approval message
  (`ENROLL_APPROVE { new_D_pub_or_H_pub_hash }`). Prevents a first-host
  compromise from bootstrapping a second authorizer. The enroll screen states
  "ADD DESKTOP — you already have N".
- **machine_name**: charset-restricted (printable ASCII subset), length-capped to
  the display width, control/format/homoglyph-stripped, NFC-normalized, rendered
  in a region it cannot occlude, labeled "unverified". Never an approval input.
- **Abort conditions**: commit mismatch (step 4); SAS mismatch (user); handshake
  failure (step 7); timeout; a second PAIR_INIT while a pairing is live (ignore).
- **Revocation / reset**: on-device authorized-daemon review view (per entry:
  fingerprint = trunc(SHA-256(X25519 static)) + a device-confirmed label);
  delete an entry to revoke that machine. Extended-hold factory reset wipes the
  whole list. Journal every add/remove with a monotonic counter.

Honesty (non-goal, stated on the screen copy and in docs): the SAS the user
compares against is drawn by the host. Pairing ASSUMES a trusted host at that
moment; it detects a USB-channel interposer and confirms the right device +
machine — it does NOT authenticate the daemon software against an already
-compromised host.

## 5. Session (Noise_KK)

- Daemon H = initiator, device D = responder. Statics = the pinned X25519 keys.
- On success: authenticated, encrypted, forward-secret transport with Noise's
  monotonic per-message counters (nonces) — this is what replay protection rests
  on. A valid session IS the proof the paired desktop is present (D1).
- Handshake DoS bounds: at most MAX_PENDING_HS concurrent half-open handshakes;
  sub-second per-attempt timeout; a live established session is NEVER evicted by
  new unauthenticated handshake traffic; rate-limit repeated handshake attempts
  and repeated AEAD failures with backoff.
- A failed AEAD decrypt does NOT advance the Noise receive counter and is a
  droppable, rate-limited event — injected garbage cannot tear down a session.

### 5.1 Architecture-B interface (frozen now, implemented later — D3)
Inside the session, immediately post-handshake for a B-enabled device:
```
UNLOCK { wrap_share }            # H -> D, in NOISE_MSG
store_key = KDF(device_secret, wrap_share)      # KDF = HKDF-SHA-256, fixed salt
```
Teardown wipes the unwrapped store + session keys on: session close, idle
timeout, or reset. v1 (C-first) does not send UNLOCK; the message type and KDF
are reserved so B lands without re-architecting.

## 6. Co-authorization — SSH userauth (daemon-initiated) — M2 FIRST

Inner records are CBOR, inside NOISE_MSG.

```
ssh -> H (ssh-agent): SSH_AGENTC_SIGN_REQUEST(tbs)   # plus session-bind binding
H: verify session-bind@openssh.com server signature; resolve host key ->
   device-pinned nickname; enforce policy; allocate request_id.
H -> D (NOISE_MSG):  SIGN_REQ {
     req_id, op: "ssh-userauth",
     tbs,                       # the exact bytes ssh will send to the server
     verified_hostkey,         # the server host key H authenticated
     hostkey_nickname,         # daemon-attested label (see P4)
     is_forwarding: bool,
     username }
D: strict-parse tbs (§6.1); if hostbound, require embedded host key ==
   verified_hostkey; else "destination unverified" state.
D: display  "SSH  <username>@<nickname>"  (+ FORWARDED banner if is_forwarding);
   wait for the button (BUTTON_WINDOW).
D -> H (NOISE_MSG):  SIGN_RESP { req_id, signature }   # only after the button
H: return signature to ssh.
```
- **req_id**: 8 random bytes from H; D dedups against DEDUP_WINDOW recent ids and
  binds the button-press decision to this req_id; a repeat is rejected.
- **Credential nonce**: the device Ed25519 signs with hedged nonces
  `r = H(TRNG(32) || monotonic_counter || key)` (never bare RFC-8032
  deterministic), with verify-after-sign.
- Deny / no session / timeout / no button -> SIGN_RESP { error } (SSH auth fails
  cleanly; the agent returns failure).

### 6.1 Strict tbs parser (device-side, decisive)
Accept EXACTLY one of, else reject:
1. RFC 4252 §7 publickey userauth blob:
   `string session_id, byte 50, string user, string "ssh-connection",
    string "publickey", bool TRUE, string pkalg, string pubkey`.
2. `publickey-hostbound-v00@openssh.com` blob: as (1) with method name replaced
   and a trailing `string server_host_key`. Device extracts it and checks
   `== verified_hostkey`.
3. SSHSIG blob: magic "SSHSIG", `namespace` in the allowlist {"git", "ssh"},
   reserved, hash_alg in {sha256, sha512}, H(message).
Anything else -> reject (blocks cross-protocol signature abuse of the SSH key).

## 7. Co-authorization — FIDO2 getAssertion (device-initiated) — M2 SECOND

```
browser -> D (TLC-1): authenticatorGetAssertion(rpId, clientDataHash, allowList)
D: build authenticatorData = rpIdHash || flags || signCount || extensions
D -> H (NOISE_MSG):  COAUTH_REQ {
     req_id, op: "fido2-assert", rpId, authenticatorData, clientDataHash,
     credential_id }
H: rpId allowlist / rate-limit / time-window policy; log; -> COAUTH_APPROVE {req_id}
     or COAUTH_DENY { req_id, reason }
D: while awaiting, stream CTAPHID keepalive @ KEEPALIVE_CADENCE; honor
     CTAPHID_CANCEL (abort, clear display, never sign).
D: on APPROVE, display "Sign in: <rpId>", wait for button; re-check the CTAP
     transaction/CID is still current + un-cancelled at button time before signing.
D: sign (authenticatorData || clientDataHash); return assertion on TLC-1.
```
- COAUTH must strictly precede any button prompt (deny/absent/timeout never
  shows a button). At most one outstanding prompt; extra getAssertions ->
  CTAP2_ERR_CHANNEL_BUSY. signCount reported as 0 on the wire (spec-legal),
  internal SE-backed counter for audit only.
- FIDO2 deadlines tighten so COAUTH_DEADLINE + user interaction fit under the
  Firefox ~30 s clamp; measure real browser behavior before finalizing.

## 8. Failure / downgrade

- No session (daemon absent / not yet unlocked): D fails closed. FIDO2 ->
  CTAP2_ERR_OPERATION_DENIED after a bounded wait (with keepalives, not instant);
  SSH signing simply unavailable.
- No "travel mode" in v1 (a deliberate non-default).
- Deployment requirements (load-bearing, documented for the user): SSH servers
  set `AuthenticationMethods publickey` with no password/keyboard-interactive
  fallback (the agent cannot stop the ssh client trying other methods); WebAuthn
  RPs treat this device as sole/primary and don't silently offer a weaker factor.

## 9. Security scope (say it plainly)

Defends: stolen/lab-attacked device alone; use from any non-paired machine; a
KEYLESS local process forging co-auth or silently downgrading; channel replay /
tamper; message substitution at approval time (via the display).
Non-goals: in-session desktop malware (co-signs by construction); a compromised
host at pairing time; jam-resistance on an OS-open HID endpoint.

## 10. Still to pin during implementation
- **req_id dedup + length** (device SIGN_REQ handler): reject `req_id.len() != 8`;
  reject any req_id in a fixed `[[u8;8]; DEDUP_WINDOW]` ring; bind the button
  decision to the exact req_id and record only on acceptance. (Shared crate has
  `SignReq::validate()` for the length/shape pre-check.)
- **chan allocation** (§3): initiator allocates a fresh non-zero chan; responder
  binds chan from the first inbound START; per-chan reassembly slots time out at
  `CKVP_REASM_TIMEOUT_MS`. Daemon currently uses a fixed chan (point-to-point ok).
- **machine_name sanitization** (§4): daemon NFC-normalizes + restricts to
  printable ASCII before PAIR_INIT; device clamps at render (truncate, isolated
  "unverified" region), never uses the name as an approval input.
- Exact CBOR field tags/ordering for each record; canonical encoding rules.
- On-device enroll-gesture duration + factory-reset hold duration; enroll-screen
  copy/color/icon.
- ENROLL_APPROVE record format (existing-daemon approval of a new one).
- Noise handshake rate-limit/backoff parameters; initiator-ephemeral replay cache.
- clientPIN policy for v1 (gate behind an established session; decouple
  PIN-lockout from destruction of the store-wrapping key via an escrowed re-wrap).
- B: KDF salt/params, wrap_share format/size, device_secret provenance.

## 11. Firmware/hardware hardening (milestone-gated)
- Remove all software reboot/DFU paths from production firmware (recovery =
  physical BOOT hold at power-on). Mule keeps its reflash hatch only behind a
  compile-time dev flag AND a physical BOOT hold; the raw pre-framing magic must
  not exist in a shipping image.
- Enable secure-boot v2, flash encryption, and disable plaintext ROM
  serial-download (eFuses) — M4/M5 gates; note this ends the easy reflash loop.
- STATUS: only a health byte unauthenticated; rich figures only inside a session.
