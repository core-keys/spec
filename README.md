# core-keys spec

The two documents that are the **source of truth** for
[core-keys](https://github.com/core-keys), a split-key hardware authenticator
for SSH and FIDO2. They outrank any code comment in any of the implementation
repositories.

- **[DESIGN.md](DESIGN.md)** — frozen decisions D1 to D4, architecture, honest
  threat claims, milestones M1 to M5, board pinout and flashing notes. Frozen
  2026-08-28.
- **[docs/coauth-protocol.md](docs/coauth-protocol.md)** — the section-numbered
  co-authorization wire protocol. Code across the other repositories cites it as
  "docs §N"; those citations are meant to stay accurate.

The invariant everything serves (docs §0): the device signs only when it has an
authenticated in-session request from the paired desktop, over the exact bytes
to be signed, AND the user presses the button after reading honest context on
the display.

Two sections are worth knowing before reading any implementation:

- **docs §10** is the list of *deliberate* gaps — req_id dedup specifics, chan
  allocation, canonical CBOR rules, ENROLL_APPROVE format, the architecture-B
  wrap layer, clientPIN policy. Things that look missing are often listed there
  on purpose.
- **docs §3.1 and §11** are why no plaintext frame may change device state.

## The core-keys repositories

| repo | what |
|---|---|
| [spec](https://github.com/core-keys/spec) | frozen design decisions and the section-numbered co-authorization wire protocol |
| [protocol](https://github.com/core-keys/protocol) | `corekeys-protocol`, the shared `no_std` wire crate |
| [daemon](https://github.com/core-keys/daemon) | `corekeys-daemon`, the desktop ssh-agent front end and Noise session owner |
| [mule-esp32s3](https://github.com/core-keys/mule-esp32s3) | ESP-IDF firmware for the protocol mule (LilyGO T-Display-S3) |
| [case-tdisplay-s3](https://github.com/core-keys/case-tdisplay-s3) | slide-in 3D-printed case for the board |

## License

Dual-licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or
the [MIT license](LICENSE-MIT), at your option. Unless you state otherwise, any
contribution you intentionally submit for inclusion in this work shall be
dual-licensed as above, without additional terms or conditions.

## Status

Design frozen; M1 (mule bring-up) in progress. Nothing in the project is fit for
real credentials yet.
