# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""
Quic Packet Parser Utility
"""

import struct
from enum import IntEnum
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

import dpkt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from pcaptoparquet.e2e_tls_utils import decode_tls_handshake


def hkdf_extract(
    algorithm: hashes.HashAlgorithm, salt: bytes, key_material: bytes
) -> bytes:
    """
    Extracts a pseudorandom key from the key_material using the salt.
    """
    h = hmac.HMAC(salt, algorithm)
    h.update(key_material)
    return h.finalize()


def hkdf_label(label: bytes, hash_value: bytes, length: int) -> bytes:
    """
    Generates a label for the HKDF Expand function.
    """
    full_label = b"tls13 " + label
    return (
        struct.pack("!HB", length, len(full_label))
        + full_label
        + struct.pack("!B", len(hash_value))
        + hash_value
    )


def hkdf_expand_label(
    algorithm: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    hash_value: bytes,
    length: int,
) -> bytes:
    """
    Expands the secret using the label and hash value.
    """
    return HKDFExpand(
        algorithm=algorithm,
        length=length,
        info=hkdf_label(label, hash_value, length),
    ).derive(secret)


def pull_uint_var(buf: bytes) -> Tuple[int, int]:
    """
    Extracts a variable-length unsigned integer from the buffer.
    """
    if not buf:
        raise IndexError("truncated QUIC varint")
    pos = 0
    prefix = buf[pos] >> 6

    if prefix == 0:
        value = buf[pos] & 0x3F
        pos += 1
    elif prefix == 1:
        if len(buf) < 2:
            raise IndexError("truncated QUIC varint")
        value = struct.unpack_from(">H", buf, pos)[0] & 0x3FFF
        pos += 2
    elif prefix == 2:
        if len(buf) < 4:
            raise IndexError("truncated QUIC varint")
        value = struct.unpack_from(">I", buf, pos)[0] & 0x3FFFFFFF
        pos += 4
    else:
        if len(buf) < 8:
            raise IndexError("truncated QUIC varint")
        value = struct.unpack_from(">Q", buf, pos)[0] & 0x3FFFFFFFFFFFFFFF
        pos += 8

    return value, pos


# Reassemble CRYPTO frame
class QuicFrameType(IntEnum):
    """QUIC Frame Types"""

    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    ACK_ECN = 0x03
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM_BASE = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    MAX_STREAMS_BIDI = 0x12
    MAX_STREAMS_UNI = 0x13
    DATA_BLOCKED = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED_BIDI = 0x16
    STREAMS_BLOCKED_UNI = 0x17
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    TRANSPORT_CLOSE = 0x1C
    APPLICATION_CLOSE = 0x1D
    HANDSHAKE_DONE = 0x1E
    DATAGRAM = 0x30
    DATAGRAM_WITH_LENGTH = 0x31


QUIC_V1_VERSION_HEX = "00000001"
INITIAL_SALT_VERSION_1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
_AEAD_TAG_LENGTH = 16
_SAMPLE_SIZE = 16
_KEY_SIZE = 16


@lru_cache(maxsize=2048)
def _initial_traffic_keys(dcid: bytes, in_label: bytes) -> Tuple[bytes, bytes, bytes]:
    """Derive QUIC v1 Initial AEAD key, IV, and header-protection key."""
    algo = hashes.SHA256()
    initial_secret = hkdf_extract(algo, INITIAL_SALT_VERSION_1, dcid)
    secret = hkdf_expand_label(algo, initial_secret, in_label, b"", algo.digest_size)
    pp_key = hkdf_expand_label(algo, secret, b"quic key", b"", _KEY_SIZE)
    iv_key = hkdf_expand_label(algo, secret, b"quic iv", b"", 12)
    hp_key = hkdf_expand_label(algo, secret, b"quic hp", b"", _KEY_SIZE)
    return pp_key, iv_key, hp_key


def unprotect_initial(
    raw_quic_packet: bytes, pn_offset: int, dcid: bytes, remainder_len: int
) -> Optional[Tuple[int, bytes]]:
    """Remove Initial header protection and AEAD.

    Tries ``client in`` then ``server in``. Returns ``(packet_number, plaintext)``
    only when the GCM tag verifies. Remainder is the QUIC Length field (PN +
    ciphertext + tag).
    """
    sample = raw_quic_packet[pn_offset + 4 : pn_offset + 4 + _SAMPLE_SIZE]
    if len(sample) < _SAMPLE_SIZE:
        return None
    for in_label in (b"client in", b"server in"):
        try:
            pp_key, iv_key, hp_key = _initial_traffic_keys(dcid, in_label)
            mask = (
                Cipher(
                    algorithms.AES(hp_key),
                    modes.ECB(),
                    backend=default_backend(),
                )
                .encryptor()
                .update(sample)
            )
            if len(mask) < 5:
                continue
            first_byte_open = raw_quic_packet[0] ^ (mask[0] & 0x0F)
            pnl = (first_byte_open & 0x03) + 1
            encrypted_pn = raw_quic_packet[pn_offset : pn_offset + pnl]
            if len(encrypted_pn) < pnl:
                continue
            pn = bytes(a ^ b for a, b in zip(encrypted_pn, mask[1 : pnl + 1]))
            payload_offset = pn_offset + pnl
            aead_len = remainder_len - pnl
            if aead_len < _AEAD_TAG_LENGTH:
                continue
            blob = raw_quic_packet[payload_offset : payload_offset + aead_len]
            if len(blob) < aead_len:
                continue
            ciphertext = blob[:-_AEAD_TAG_LENGTH]
            tag = blob[-_AEAD_TAG_LENGTH:]
            iv = (int.from_bytes(iv_key, "big") ^ int.from_bytes(pn, "big")).to_bytes(
                12, "big"
            )
            aad = bytearray(raw_quic_packet[:payload_offset])
            aad[0] = first_byte_open
            aad[pn_offset : pn_offset + pnl] = pn
            decryptor = Cipher(
                algorithms.AES(pp_key),
                modes.GCM(iv, tag),
                backend=default_backend(),
            ).decryptor()
            decryptor.authenticate_additional_data(bytes(aad))
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return int.from_bytes(pn, "big"), plaintext
        except (InvalidTag, ValueError, IndexError):
            continue
    return None


def _skip_ack_frame(payload: bytes, pos: int, ecn: bool) -> int:
    """Advance past an ACK or ACK_ECN frame body (RFC 9000 §19.3)."""
    _, n = pull_uint_var(payload[pos:])
    pos += n
    _, n = pull_uint_var(payload[pos:])
    pos += n
    range_count, n = pull_uint_var(payload[pos:])
    pos += n
    _, n = pull_uint_var(payload[pos:])
    pos += n
    for _ in range(range_count):
        _, n = pull_uint_var(payload[pos:])
        pos += n
        _, n = pull_uint_var(payload[pos:])
        pos += n
    if ecn:
        for _ in range(3):
            _, n = pull_uint_var(payload[pos:])
            pos += n
    return pos


class E2EQuic:
    """
    Simple QUIC Packet Parser
    """

    @staticmethod
    def parse_crypto_frame(payload: bytes) -> bytes:
        """
        Parse the CRYPTO frame
        """

        crypto_frame: Dict[int, bytes] = {}

        read_pos = 0
        while read_pos < len(payload):
            while (
                read_pos < len(payload) and payload[read_pos] == QuicFrameType.PADDING
            ):
                read_pos += 1

            if read_pos >= len(payload):
                break

            try:
                frame_type = payload[read_pos]
                read_pos += 1
                if frame_type == QuicFrameType.PING:
                    continue
                if frame_type == QuicFrameType.ACK:
                    read_pos = _skip_ack_frame(payload, read_pos, False)
                    continue
                if frame_type == QuicFrameType.ACK_ECN:
                    read_pos = _skip_ack_frame(payload, read_pos, True)
                    continue
                if frame_type != QuicFrameType.CRYPTO:
                    break
                frame_offset, frame_offset_len = pull_uint_var(payload[read_pos:])
                read_pos += frame_offset_len
                frame_length, frame_length_len = pull_uint_var(payload[read_pos:])
                read_pos += frame_length_len
                frame_data = payload[read_pos : read_pos + frame_length]
                crypto_frame[frame_offset] = frame_data
                read_pos += frame_length

            except (IndexError, struct.error):
                break

        # Sort the frames by offset and reassemble the CRYPTO frame
        return b"".join(frame_data for _, frame_data in sorted(crypto_frame.items()))

    def __init__(self, raw_quic_packet: bytes):
        """
        Initialize the QUIC Packet Parser
        """
        try:
            self.packet_number: Optional[int] = None
            self.crypto_data = b""
            #   Extract the first byte (header form and type)
            first_byte = raw_quic_packet[0]

            if (first_byte >> 6) != 0b11:
                self.is_long_header = False
                #   Short Packet Type (2),
                self.type = "Short Header: Payload"
                #   Spin Bit (1),
                self.spin = (first_byte & 0b00100000) >> 5
                #   Reserved Bits (2),
                #   Key Phase (1),
                #   Packet Number Length (2),
                #   Packet Number (8..32),     # Protected
                #   Protected Payload (0..24), # Skipped Part
                #   Protected Payload (128),   # Sampled Part
                #   Protected Payload (..)     # Remainder
            else:
                self.is_long_header = True
                #   Long Packet Type (2),
                #   Header Form (1) = 1,
                #   Fixed Bit (1) = 1,
                #   Long Packet Type (2) = 0,
                #   Reserved Bits (2),         # Protected
                #   Packet Number Length (2),  # Protected
                self.ptype = (first_byte & 0b00110000) >> 4
                #   Version (32),

                # Extract the version (4 bytes starting at byte 1)
                self.quic_version = raw_quic_packet[1:5].hex()

                #   DCID Len (8),
                dcid_length = raw_quic_packet[5]

                #   Destination Connection ID (0..160),
                self.dcid = raw_quic_packet[6 : 6 + dcid_length]

                #   SCID Len (8),
                scid_length = raw_quic_packet[6 + dcid_length]

                #   Source Connection ID (0..160),
                self.scid = raw_quic_packet[
                    7 + dcid_length : 7 + dcid_length + scid_length
                ]

                #   Packet Number (8..32),     # Protected
                #   Protected Payload (0..24), # Skipped Part
                #   Protected Payload (128),   # Sampled Part
                #   Protected Payload (..)     # Remainder
                # }
                after_scid = 7 + dcid_length + scid_length
                if self.ptype == 0:

                    #   Token Length (i),
                    token_length, token_pos_len = pull_uint_var(
                        raw_quic_packet[after_scid:]
                    )
                    #   Token (..),
                    token_start = after_scid + token_pos_len
                    self.token = raw_quic_packet[
                        token_start : token_start + token_length
                    ]

                    #   Length (i),
                    length_start = token_start + token_length
                    self.payload_length, plength_pos_len = pull_uint_var(
                        raw_quic_packet[length_start:]
                    )

                    self.type = "Long Header: Initial"
                    pn_offset = after_scid + token_pos_len + token_length
                    pn_offset += plength_pos_len

                    if self.quic_version == QUIC_V1_VERSION_HEX:
                        opened = unprotect_initial(
                            raw_quic_packet,
                            pn_offset,
                            self.dcid,
                            self.payload_length,
                        )
                        if opened is not None:
                            self.packet_number, plaintext = opened
                            try:
                                self.crypto_data = E2EQuic.parse_crypto_frame(plaintext)
                            except Exception:  # pylint: disable=broad-except
                                self.crypto_data = b""

                elif self.ptype == 1:
                    self.type = "Long Header: 0-RTT"
                    self.payload_length, _ = pull_uint_var(raw_quic_packet[after_scid:])

                elif self.ptype == 2:
                    self.type = "Long Header: Handshake"

                    #   Length (i),
                    self.payload_length, plength_pos_len = pull_uint_var(
                        raw_quic_packet[after_scid:]
                    )

                elif self.ptype == 3:
                    self.type = "Long Header: Retry"
                    self.payload_length = 0

                else:
                    self.type = "Long Header: Other"
                    #   Length (i),
                    self.payload_length, plength_pos_len = pull_uint_var(
                        raw_quic_packet[after_scid:]
                    )
        except IndexError:
            pass

    def get_crypto_data(self) -> bytes:
        """
        Get the CRYPTO data
        """
        try:
            return self.crypto_data
        except AttributeError:
            return b""

    def __repr__(self) -> str:
        l_ = []
        for attr in ["type", "quic_version", "dcid", "scid", "payload_length"]:
            l_.append(f"{attr}={str(getattr(self, attr))}")
        return f"{self.__class__.__name__}({', '.join(l_)})"

    def to_json(self) -> dict[str, Any]:
        """
        Convert the E2EQuic object to a dictionary.
        """
        d_ = {}
        for attr in ["type", "quic_version", "dcid", "scid", "payload_length"]:
            d_[attr] = getattr(self, attr)
        return d_


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the RTP protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Decode the application layer as QUIC.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        QUIC data dpkt object.
    """

    quic = None

    if not isinstance(transport, dpkt.udp.UDP):
        return None

    if len(app) > 0:
        quic = app
        firstbyte = struct.unpack("!B", quic[0:1])[0]
        if (firstbyte & 0b10000000) >> 7 == 0 and (firstbyte & 0b01000000) >> 6 == 0:
            setattr(packet, "app_type", "GQUIC")
            cid_len = (firstbyte & 0b00001000) >> 3
            pkt_len = ((firstbyte & 0b00110000) >> 4) + 1
            delta = 4 * (firstbyte & 0b00000001)
            if cid_len > 0:
                setattr(packet, "app_session", struct.unpack("!Q", quic[1:9])[0])
                if pkt_len == 1:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!B", quic[9 + delta : 10 + delta])[0],
                    )
                elif pkt_len == 2:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!H", quic[9 + delta : 11 + delta])[0],
                    )
                elif pkt_len == 3:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!L", b"\x00" + quic[9 + delta : 12 + delta])[0],
                    )
                else:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!L", quic[9 + delta : 13 + delta])[0],
                    )
            else:
                if pkt_len == 1:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!B", quic[1 + delta : 2 + delta])[0],
                    )
                elif pkt_len == 2:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!H", quic[1 + delta : 3 + delta])[0],
                    )
                elif pkt_len == 3:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!L", b"\x00" + quic[1 + delta : 4 + delta])[0],
                    )
                else:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!L", quic[1 + delta : 5 + delta])[0],
                    )
            seq = getattr(packet, "app_seq", None)
            if seq is not None:
                setattr(packet, "transport_pkn", seq)
        else:
            setattr(packet, "app_type", "QUIC")
            try:
                quic_pkt = E2EQuic(quic)
                if quic_pkt.is_long_header:
                    # Long header
                    quic_str = str(quic_pkt)
                    if getattr(packet, "transport_dst_port") == 443:
                        setattr(packet, "app_request", quic_str)
                    else:
                        setattr(packet, "app_response", quic_str)

                    if quic_pkt.ptype == 0:
                        # type = "Initial"
                        try:
                            _, app_request, app_response, e2e_sni = (
                                decode_tls_handshake(
                                    quic_pkt.get_crypto_data(),
                                    getattr(packet, "app_request"),
                                    getattr(packet, "app_response"),
                                )
                            )
                            setattr(packet, "e2e_sni", e2e_sni)
                            setattr(packet, "app_request", app_request)
                            setattr(packet, "app_response", app_response)
                        except Exception:  # pylint: disable=broad-except
                            setattr(packet, "e2e_sni", None)

                        setattr(packet, "app_session", quic_pkt.dcid.hex())
                        if quic_pkt.packet_number is not None:
                            setattr(packet, "transport_pkn", quic_pkt.packet_number)

                    # elif ptype == 2:
                    #  TODO: "Handshake" implementation

                else:
                    # Short Header
                    setattr(packet, "transport_spin", quic_pkt.spin)

            except (dpkt.UnpackError, struct.error, AttributeError):
                quic = None

    if quic is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(quic)
