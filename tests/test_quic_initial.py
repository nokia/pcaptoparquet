# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for QUIC Initial unprotect and GQUIC transport_pkn."""

import os
import struct
import unittest
from types import SimpleNamespace

import dpkt
import polars as pl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pcaptoparquet import E2EConfig, E2EPcap
from pcaptoparquet.e2e_quic import (
    E2EQuic,
    _initial_traffic_keys,
    decode,
    pull_uint_var,
    unprotect_initial,
)

from .test_utils import configure_dirs


def _quic_varint(n: int) -> bytes:
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack(">H", 0x4000 | n)
    raise ValueError("varint too large for test helper")


def _crypto_frame(data: bytes, offset: int = 0) -> bytes:
    return bytes([0x06]) + _quic_varint(offset) + _quic_varint(len(data)) + data


def _protect_initial(
    dcid: bytes,
    plaintext: bytes,
    packet_number: int,
    in_label: bytes = b"client in",
    token: bytes = b"",
) -> bytes:
    """Build a one-byte-PN QUIC v1 Initial (empty SCID)."""
    pnl = 1
    first = 0xC0
    scid = b""
    hdr = (
        bytes([first])
        + bytes.fromhex("00000001")
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + _quic_varint(len(token))
        + token
    )
    pn_bytes = packet_number.to_bytes(pnl, "big")
    remainder = pnl + len(plaintext) + 16
    assert remainder < 64
    length = bytes([remainder])
    unprot = hdr + length + pn_bytes
    pn_offset = len(hdr) + len(length)
    pp_key, iv_key, hp_key = _initial_traffic_keys(dcid, in_label)
    iv = (int.from_bytes(iv_key, "big") ^ int.from_bytes(pn_bytes, "big")).to_bytes(
        12, "big"
    )
    encryptor = Cipher(
        algorithms.AES(pp_key), modes.GCM(iv), backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(unprot)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    packet = bytearray(unprot + ciphertext + encryptor.tag)
    sample = bytes(packet[pn_offset + 4 : pn_offset + 20])
    mask = (
        Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
        .encryptor()
        .update(sample)
    )
    packet[0] ^= mask[0] & 0x0F
    packet[pn_offset] ^= mask[1]
    return bytes(packet)


class TestQuicInitial(unittest.TestCase):
    def test_unprotect_client_initial_packet_number(self) -> None:
        dcid = bytes.fromhex("0102030405060708")
        plaintext = b"\x00" * 32
        packet_number = 7
        raw = _protect_initial(dcid, plaintext, packet_number)
        pn_offset = 1 + 4 + 1 + len(dcid) + 1 + 0 + 1 + 1
        opened = unprotect_initial(raw, pn_offset, dcid, 1 + 32 + 16)
        self.assertIsNotNone(opened)
        assert opened is not None
        self.assertEqual(opened[0], packet_number)
        self.assertEqual(opened[1], plaintext)

    def test_unprotect_server_initial_packet_number(self) -> None:
        dcid = bytes.fromhex("0102030405060708")
        plaintext = b"\x00" * 32
        packet_number = 4
        raw = _protect_initial(dcid, plaintext, packet_number, in_label=b"server in")
        pn_offset = 1 + 4 + 1 + len(dcid) + 1 + 0 + 1 + 1
        opened = unprotect_initial(raw, pn_offset, dcid, 1 + 32 + 16)
        self.assertIsNotNone(opened)
        assert opened is not None
        self.assertEqual(opened[0], packet_number)
        self.assertEqual(opened[1], plaintext)

    def test_unprotect_wrong_key_material_is_none(self) -> None:
        dcid = bytes.fromhex("0102030405060708")
        raw = _protect_initial(dcid, b"\x00" * 32, 1)
        pn_offset = 1 + 4 + 1 + len(dcid) + 1 + 0 + 1 + 1
        opened = unprotect_initial(raw, pn_offset, b"\xff" * 8, 1 + 32 + 16)
        self.assertIsNone(opened)

    def test_e2e_quic_sets_initial_packet_number(self) -> None:
        dcid = bytes.fromhex("0102030405060708")
        raw = _protect_initial(dcid, b"\x00" * 32, 9)
        pkt = E2EQuic(raw)
        self.assertEqual(pkt.type, "Long Header: Initial")
        self.assertEqual(pkt.packet_number, 9)

    def test_decode_sets_transport_pkn_on_initial(self) -> None:
        dcid = bytes.fromhex("aabbccddeeff0011")
        raw = _protect_initial(dcid, b"\x00" * 32, 3)
        packet = SimpleNamespace(
            transport_dst_port=443,
            app_request=None,
            app_response=None,
        )
        out = decode(packet, dpkt.udp.UDP(), raw)
        self.assertIsNotNone(out)
        self.assertEqual(packet.app_type, "QUIC")
        self.assertEqual(packet.transport_pkn, 3)
        self.assertIsNone(getattr(packet, "app_seq", None))

    def test_gquic_copies_app_seq_to_transport_pkn(self) -> None:
        # Public flags: no CID, 1-byte PN, value 5.
        raw = bytes([0x00, 5]) + b"\x00" * 8
        packet = SimpleNamespace()
        decode(packet, dpkt.udp.UDP(), raw)
        self.assertEqual(packet.app_type, "GQUIC")
        self.assertEqual(packet.app_seq, 5)
        self.assertEqual(packet.transport_pkn, 5)

    def test_zero_rtt_type_label(self) -> None:
        raw = bytes([0xD0]) + bytes.fromhex("00000001") + bytes([0, 0, 5])
        pkt = E2EQuic(raw)
        self.assertTrue(pkt.is_long_header)
        self.assertEqual(pkt.type, "Long Header: 0-RTT")
        self.assertEqual(pkt.payload_length, 5)

    def test_retry_type_label(self) -> None:
        raw = bytes([0xF0]) + bytes.fromhex("00000001") + bytes([0, 0])
        pkt = E2EQuic(raw)
        self.assertTrue(pkt.is_long_header)
        self.assertEqual(pkt.type, "Long Header: Retry")
        self.assertEqual(pkt.payload_length, 0)

    def test_ietf_quic_v1_capture_sets_transport_pkn(self) -> None:
        dirs = configure_dirs()
        path = os.path.join(
            dirs["ddir"],
            "00_functional",
            "05_applications",
            "32.ietf_quic_v1.pcap.gz",
        )
        df = E2EPcap(
            {"pcap_name": os.path.basename(path)},
            "Client",
            path,
            E2EConfig(),
        ).export(return_df=True)
        quic = df.filter(pl.col("app_type") == "QUIC")
        self.assertGreater(quic.height, 0)
        with_pkn = quic.filter(pl.col("transport_pkn").is_not_null())
        self.assertGreater(with_pkn.height, 0)

    def test_parse_crypto_after_ping(self) -> None:
        payload = b"\x01" + _crypto_frame(b"hello")
        self.assertEqual(E2EQuic.parse_crypto_frame(payload), b"hello")

    def test_parse_crypto_after_ack(self) -> None:
        ack = bytes([0x02, 0, 0, 0, 0])
        payload = ack + _crypto_frame(b"world")
        self.assertEqual(E2EQuic.parse_crypto_frame(payload), b"world")

    def test_parse_truncated_ack_does_not_raise(self) -> None:
        self.assertEqual(E2EQuic.parse_crypto_frame(b"\x02"), b"")

    def test_pull_uint_var_truncated_raises_indexerror(self) -> None:
        with self.assertRaises(IndexError):
            pull_uint_var(b"\x40")
        # Truncated Initial token-length varint must not escape E2EQuic.
        E2EQuic(bytes([0xC0]) + bytes.fromhex("00000001") + bytes([0, 0, 0x40]))

    def test_initial_with_64_byte_token(self) -> None:
        dcid = bytes.fromhex("0102030405060708")
        token = b"\xab" * 64
        raw = _protect_initial(dcid, b"\x00" * 32, 11, token=token)
        pkt = E2EQuic(raw)
        self.assertEqual(pkt.token, token)
        self.assertEqual(pkt.packet_number, 11)

    def test_gquic_3byte_pn_with_cid(self) -> None:
        cid = b"\x11" * 8
        raw = bytes([0x28]) + cid + bytes([0x01, 0x02, 0x03]) + b"\x00" * 8
        packet = SimpleNamespace()
        decode(packet, dpkt.udp.UDP(), raw)
        self.assertEqual(packet.app_type, "GQUIC")
        self.assertEqual(packet.app_seq, 0x010203)
        self.assertEqual(packet.transport_pkn, 0x010203)


if __name__ == "__main__":
    unittest.main()
