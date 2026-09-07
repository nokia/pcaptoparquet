---
name: repo-protocol-decoder
description: >-
  Adds or changes pcaptoparquet application/transport protocol decoders
  (decode, get_metadata, E2EConfig port maps, QUIC Initial unprotect). Use when
  editing e2e_quic, e2e_http, e2e_dns, e2e_ping, tests/config/modules, or
  schema fields such as app_type, transport_pkn, or e2e_sni.
---

# Protocol decoders (this project)

pcaptoparquet decodes **headers and public handshake bytes** into the parquet schema in **`schema.md`**. It does not implement congestion control, session key recovery, or full encrypted payloads.

## Built-in vs extension

| Kind | Where | Registration |
|------|-------|----------------|
| Built-in | `pcaptoparquet/e2e_{ping,dns,http,https,quic}.py` | `E2EConfig.load_mapping_from_file` default ports |
| Extension | `tests/config/modules/*.py` (examples) | JSON `protocols` / `overrides` via `--config` |

Each module must expose:

- `decode(packet, transport, app) -> Optional[bytes]` — set attributes on `packet`, return remaining payload or `None` on failure.
- `get_metadata() -> dict[str, str]` — extra `E2EPacket` columns (usually `{}`).

On decode failure, clear `app_type` / `app_seq` / `app_request` / `app_response` (and do not leave a partial `app_type`).

## Schema fields

Do not invent parquet columns. If a field is missing:

1. Add it to `E2EPacket._decoder_meta` and `schema.md`.
2. Initialize it in `create_empty_attr` if needed.
3. Add or extend unit tests.

Usual app fields: `app_type`, `app_session`, `app_seq`, `app_request`, `app_response`, `e2e_sni`.

Transport fields reused across protocols:

- `transport_pkn` — visible packet/sequence number (SCTP, ICMP echo, GQUIC public PN, IETF QUIC v1 **Initial** after unprotect).
- `transport_spin` — QUIC short-header spin bit.
- `transport_cid` — e.g. ICMP echo id.

## QUIC (`e2e_quic.py`)

- Default port: UDP/443.
- **IETF QUIC v1 Initial** (`version == 00000001`): remove header protection and AEAD with the **public Initial salt** (RFC 9001). Try `client in` then `server in`. Commit `transport_pkn` and CRYPTO/TLS only when the GCM tag verifies.
- `remainder_len` is the QUIC **Length** field (packet number + ciphertext + tag), not the UDP datagram size (coalesced packets).
- Draft versions and 0-RTT/Handshake/1-RTT payloads stay protected; still label long-header types and short-header spin.
- GQUIC public headers copy the public packet number to `app_seq` and `transport_pkn`.

Do not add QUIC v2 salts, retry integrity, or 1-RTT decryption unless the schema and tests are updated for that scope.

## Tests

- Synthetic / crypto round-trip: `tests/test_quic_initial.py`.
- Real captures: `tests/test_module.py` (`20_udp_gquic`, `21_udp_ietf_quic`, `32.ietf_quic_v1`, …).
- Follow **repo-fast-test-selection** and **global-post-change-compliance**.
