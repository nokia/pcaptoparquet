# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""MCP prompt text: one list_captures, then one run(). Hosts may ignore prompts."""

TCP_SETUP = """\
Call list_captures once, then one run. TCP flags are booleans
(transport_syn_flag, transport_ack_flag, …), not a bitmask.
transport_pkn is not TCP sequence (that is transport_seq).

{"steps": [
  {"op": "filter", "expr": {"and": [
    {"eq": [{"col": "transport_type"}, {"lit": "TCP"}]},
    {"col": "transport_syn_flag"},
    {"not": {"col": "transport_ack_flag"}}
  ]}},
  {"op": "select", "columns": ["ip_src", "ip_dst", "transport_src_port",
    "transport_dst_port"]},
  {"op": "unique", "columns": ["ip_src", "ip_dst", "transport_src_port",
    "transport_dst_port"]}
]}
"""

SNI_IN_CAPTURE = """\
Call list_captures once, then one run. e2e_sni is SNI from TLS ClientHello
and IETF QUIC v1 Initial CRYPTO only. Preset sni_table is the same job.

{"steps": [
  {"op": "filter", "expr": {"and": [
    {"is_not_null": {"col": "e2e_sni"}},
    {"ne": [{"col": "e2e_sni"}, {"lit": ""}]}
  ]}},
  {"op": "group_by", "keys": ["e2e_sni"], "agg": [{"op": "len", "alias": "n"}]},
  {"op": "sort", "by": ["n"], "descending": true}
]}
"""

TRAFFIC_MIX = """\
Call list_captures once, then one run. If the capture is mostly UDP with
app_type QUIC, say so; do not assume TCP. Preset summarize_capture covers mix.

{"steps": [
  {"op": "group_by", "keys": ["transport_type"],
   "agg": [{"op": "len", "alias": "n"}]}
]}
"""

GROUP_THEN_JOIN = """\
Call list_captures once, then one run. To attach per-(ip_src, ip_dst)
aggregates back onto packets, group_by then join_packets (same capture).
join_packets is not allowed on num (that would be a packet self-join).
After join_packets, group_by/unique so the final frame has no num
(aggregate caps, full distinct list). Packet-shaped results are a
5-row sample unless you pass head.

{"steps": [
  {"op": "group_by", "keys": ["ip_src", "ip_dst"],
   "agg": [{"op": "len", "alias": "n"}]},
  {"op": "join_packets", "on": ["ip_src", "ip_dst"], "how": "inner"},
  {"op": "select", "columns": ["ip_src", "ip_dst", "n"]},
  {"op": "unique", "columns": ["ip_src", "ip_dst", "n"]}
]}
"""

WHO_TALKS = """\
Call list_captures once, then one run. Use preset conversations (tshark
conv,ip) or endpoints (tshark endpoints,ip), not both. bytes columns are
sum(ip_len), not wire bytes. list_flows is a 5-tuple plus transport_cid;
conversations type=tcp is the 4-tuple without CID.

run(capture=..., preset="conversations")
# or: run(capture=..., preset="endpoints")
"""
