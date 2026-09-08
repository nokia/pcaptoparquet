# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Named MCP prompt text. Hosts may ignore prompts; tools still stand alone."""

TCP_SETUP = """\
Use list_captures, then tcp_setup on a relative capture path.
Look for SYN without matching ACK, RST, and FIN. TCP flags are boolean
columns (transport_syn_flag, transport_ack_flag, transport_rst_flag,
transport_fin_flag), not a bitmask. Do not use transport_pkn as TCP sequence;
that is transport_seq.
"""

SNI_IN_CAPTURE = """\
Use list_captures, then sni_table on a relative capture path.
e2e_sni is Server Name Indication from TLS ClientHello and IETF QUIC version 1
Initial CRYPTO only. Encrypted payloads and short-header QUIC are not decoded.
"""

TRAFFIC_MIX = """\
Use list_captures, then summarize_capture on a relative capture path.
Report transport_type mix, app_type mix, tunnel types, and top talkers.
If the capture is mostly UDP with app_type QUIC, say so; do not assume TCP.
"""
