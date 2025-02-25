# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""
Quic Packet Parser Utility
"""
import operator
import struct
from enum import IntEnum
from typing import Any, Dict, Optional, Tuple

import dpkt
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
    pos = 0
    prefix = buf[pos] >> 6

    if prefix == 0:
        value = buf[pos] & 0x3F
        pos += 1
    elif prefix == 1:
        assert len(buf) > 1
        value = struct.unpack_from(">H", buf, pos)[0] & 0x3FFF
        pos += 2
    elif prefix == 2:
        assert len(buf) > 3
        value = struct.unpack_from(">I", buf, pos)[0] & 0x3FFFFFFF
        pos += 4
    else:
        assert len(buf) > 7
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


class E2EQuicInitial:
    """
    Simple QUIC Initial Packet Parser
    """

    # Initial Packet {
    INITIAL_CIPHER_SUITE = "AES_128_GCM_SHA256"
    INITIAL_SALT_VERSION_1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    # INITIAL_SALT_VERSION_2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
    SAMPLE_SIZE = 16

    v1_salt = INITIAL_SALT_VERSION_1
    v1_algorithm = hashes.SHA256()

    AEAD_KEY_LENGTH_MAX = 32
    AEAD_NONCE_LENGTH = 12
    AEAD_TAG_LENGTH = 16
    PACKET_LENGTH_MAX = 1500

    hp_cipher_name = b"aes-128-ecb"
    aead_cipher_name = b"aes-128-gcm"
    key_size = 16

    def __init__(self, raw_quic_packet: bytes, pn_offset: int, dcid: bytes):
        """
        Initialize the QUIC Packet Parser
        """
        # uint8_t sample[16];
        # tvb_memcpy(tvb, sample, pn_offset + 4, 16);
        sample_offset = pn_offset + 4
        sample = raw_quic_packet[
            sample_offset : sample_offset + E2EQuicInitial.SAMPLE_SIZE + 1
        ]
        # header = bytearray(raw_quic_packet[: sample_offset + 1])
        initial_secret = hkdf_extract(
            E2EQuicInitial.v1_algorithm, E2EQuicInitial.v1_salt, dcid
        )
        client_secret = hkdf_expand_label(
            E2EQuicInitial.v1_algorithm,
            initial_secret,
            b"client in",
            b"",
            E2EQuicInitial.v1_algorithm.digest_size,
        )
        pp_key = hkdf_expand_label(
            E2EQuicInitial.v1_algorithm,
            client_secret,
            b"quic key",
            b"",
            E2EQuicInitial.key_size,
        )
        iv_key = hkdf_expand_label(
            E2EQuicInitial.v1_algorithm, client_secret, b"quic iv", b"", 12
        )
        hp_key = hkdf_expand_label(
            E2EQuicInitial.v1_algorithm,
            client_secret,
            b"quic hp",
            b"",
            E2EQuicInitial.key_size,
        )

        # Header encryption using AES
        header_encryptor = Cipher(
            algorithms.AES(hp_key), modes.ECB(), backend=default_backend()
        ).encryptor()

        mask = header_encryptor.update(sample)

        # Extract first byte and calculate packet number length (pnl)
        first_byte_open = raw_quic_packet[0] ^ (mask[0] & 0x0F)

        pnl = (first_byte_open & 0x03) + 1

        # Decrypt packet number
        encrypted_pn = raw_quic_packet[pn_offset : pn_offset + pnl]
        self.pn = bytes(map(operator.xor, encrypted_pn, mask[1 : pnl + 1]))
        self.payload_offset = pn_offset + pnl

        # Generate IV
        iv = (int.from_bytes(iv_key, "big") ^ int.from_bytes(self.pn, "big")).to_bytes(
            12, "big"
        )

        # Payload decryption using AES-GCM
        self.payload_decryptor = Cipher(
            algorithms.AES(pp_key), modes.GCM(iv), backend=default_backend()
        ).decryptor()

    def get_packet_number(self) -> bytes:
        """
        Get the packet number
        """
        return self.pn

    def get_payload_offset(self) -> int:
        """
        Get the payload offset
        """
        return self.payload_offset


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
            while payload[read_pos] == QuicFrameType.PADDING and read_pos < len(
                payload
            ):
                read_pos += 1

            if read_pos >= len(payload):
                break

            try:
                frame_type = payload[read_pos]
                read_pos += 1
                frame_offset, frame_offset_len = pull_uint_var(payload[read_pos:])
                read_pos += frame_offset_len
                frame_length, frame_length_len = pull_uint_var(payload[read_pos:])
                read_pos += frame_length_len
                frame_data = payload[read_pos : read_pos + frame_length]

                if frame_type == QuicFrameType.CRYPTO:
                    # Store the frame crypto data for reassembly
                    crypto_frame[frame_offset] = frame_data

                read_pos += frame_length

            except AssertionError:
                break

        # Sort the frames by offset and reassemble the CRYPTO frame
        return b"".join(frame_data for _, frame_data in sorted(crypto_frame.items()))

    def __init__(self, raw_quic_packet: bytes):
        """
        Initialize the QUIC Packet Parser
        """
        try:
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
                if self.ptype == 0:

                    #   Token Length (i),
                    token_length, token_pos_len = pull_uint_var(
                        raw_quic_packet[7 + dcid_length + scid_length :]
                    )
                    #   Token (..),
                    self.token = raw_quic_packet[
                        8
                        + dcid_length
                        + scid_length : 8
                        + dcid_length
                        + scid_length
                        + token_length
                    ]

                    #   Length (i),
                    self.payload_length, plength_pos_len = pull_uint_var(
                        raw_quic_packet[8 + dcid_length + scid_length + token_length :]
                    )

                    self.type = "Long Header: Initial"
                    # pn_offset is the start of the Packet Number field.
                    # // PKN is after type(1) + version(4) + DCIL+DCID + SCIL+SCID
                    # unsigned pn_offset = 1 + 4 + 1 + dcid.len + 1 + scid.len;
                    pn_offset = 1 + 4 + 1 + dcid_length + 1 + scid_length

                    # if (long_packet_type == QUIC_LPT_INITIAL) {
                    #     pn_offset += tvb_get_varint(tvb, pn_offset, 8, &token_length,
                    #                                 ENC_VARINT_QUIC);
                    pn_offset += token_pos_len  # To be updated varint
                    #     pn_offset += (unsigned)token_length;
                    pn_offset += token_length
                    # }
                    # pn_offset += tvb_get_varint(tvb, pn_offset, 8, &payload_length,
                    #                             ENC_VARINT_QUIC);
                    pn_offset += plength_pos_len  # To be updated varint

                    quic_initial = E2EQuicInitial(raw_quic_packet, pn_offset, self.dcid)

                    # Replace with actual protected payload
                    self.packet_number = quic_initial.get_packet_number()
                    payload_offset = quic_initial.get_payload_offset()
                    # Decrypt payload and verify
                    payload = quic_initial.payload_decryptor.update(
                        raw_quic_packet[
                            payload_offset : payload_offset + self.payload_length
                        ]
                    )
                    self.crypto_data = E2EQuic.parse_crypto_frame(payload)

                elif self.ptype == 2:
                    self.type = "Long Header: Handshake"

                    #   Length (i),
                    self.payload_length, plength_pos_len = pull_uint_var(
                        raw_quic_packet[8 + dcid_length + scid_length :]
                    )

                else:
                    self.type = "Long Header: Other"
                    #   Length (i),
                    self.payload_length, plength_pos_len = pull_uint_var(
                        raw_quic_packet[8 + dcid_length + scid_length :]
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
                        struct.unpack("!L", quic[8 + delta : 12 + delta])[0]
                        & 0x00FFFFFF,
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
                        struct.unpack("!L", quic[0 + delta : 4 + delta])[0]
                        & 0x00FFFFFF,
                    )
                else:
                    setattr(
                        packet,
                        "app_seq",
                        struct.unpack("!L", quic[1 + delta : 5 + delta])[0],
                    )
        else:
            setattr(packet, "app_type", "QUIC")
            try:
                quic_pkt = E2EQuic(quic)
                if quic_pkt.is_long_header:
                    # Long header
                    quic_str = str(quic_pkt)
                    if quic_pkt.ptype == 0:
                        # type = "Initial"
                        setattr(packet, "app_request", quic_str)
                        try:
                            (_, app_request, app_response, e2e_sni) = (
                                decode_tls_handshake(
                                    quic_pkt.get_crypto_data(),
                                    getattr(packet, "app_request"),
                                    getattr(packet, "app_response"),
                                )
                            )
                            setattr(packet, "app_session", quic_pkt.dcid.hex())
                            setattr(packet, "app_request", app_request)
                            setattr(packet, "app_response", app_response)
                            setattr(packet, "e2e_sni", e2e_sni)
                        except dpkt.ssl.SSL3Exception:
                            quic = None

                    # elif ptype == 2:
                    #  TODO: "Handshake" implementation
                    else:
                        if getattr(packet, "transport_dst_port") == 443:
                            setattr(packet, "app_request", quic_str)
                        else:
                            setattr(packet, "app_response", quic_str)

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
