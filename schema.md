# Data Schema

The proposed data schema prioritizes the main areas of bulk PCAP processing, such as:

- Network Performance Monitoring and Optimization
- Troubleshooting Network Issues
- Security Auditing and Diagnosis

In all these cases, the main goal is to characterize traffic patterns and behaviors. In most cases, application data will be encrypted, making it impossible to decode upper layer protocols.

We propose the following data schema for PCAP parquet based on the above assumption:

## Packet Information

These fields store packet number and packet timestamp:

| Column name | Column type |
|-------------|-------------|
| **num** | UInt32 |
| **utcdatetime** | datetime64[ns, UTC] |

## Outer Link Layer and Tunnel Information

These fields have the outer link layer information normally associated with the physical collection point. In some PCAP encapsulations, this information may be missing. This implementation assumes Ethernet, VLAN, and MPLS. Adding other link layer technologies could be explored in the future.

| Column name | Column type |
|-------------|-------------|
| **eth_src**| category |
| **eth_dst**| category |
| **eth_vlan_tags**| string |
| **eth_mpls_labels**| string |
| **tunel**| string |

## Inner Network Layer Information

These fields capture IPv4, IPv6, and ESP information for the inner protocols layer (IP layer closer to the actual application data):

| Column name | Column type |
|-------------|-------------|
| **ip_version**| category|
| **ip_src**| category|
| **ip_dst**| category|
| **ip_dscp**| category|
| **ip_id**| UInt16|
| **ip_ttl**| UInt8|
| **ip_len**| UInt16|
| **ip_frag**| boolean|
| **esp_spi**| UInt32|
| **esp_seq**| UInt32|

## Inner Transport Layer Information

These fields capture information for UDP, TCP, ICMP, SCTP, and QUIC at the inner protocol layer, which is closer to the actual application data. This set of fields is crucial for analyzing application performance and security:

| Column name | Column type |
|-------------|-------------|
| **transport_type**| category |
| **transport_header_len**| UInt16 |
| **transport_options_len**| UInt16 |
| **transport_data_len**| UInt16 |
| **transport_capture_len**| UInt16 |
| **transport_src_port**| UInt16 |
| **transport_dst_port**| UInt16 |
| **transport_fin_flag**| boolean |
| **transport_syn_flag**| boolean |
| **transport_rst_flag**| boolean |
| **transport_push_flag**| boolean |
| **transport_ack_flag**| boolean |
| **transport_urg_flag**| boolean |
| **transport_ece_flag**| boolean |
| **transport_cwr_flag**| boolean |
| **transport_ns_flag**| boolean |
| **transport_seq**| UInt32 |
| **transport_ack**| UInt32 |
| **transport_win**| UInt16 |
| **transport_mss**| UInt16 |
| **transport_wscale**| UInt16 |
| **transport_sackok**| boolean |
| **transport_sack1_from**| UInt32 |
| **transport_sack1_to**| UInt32 |
| **transport_sack2_from**| UInt32 |
| **transport_sack2_to**| UInt32 |
| **transport_sack3_from**| UInt32 |
| **transport_sack3_to**| UInt32 |
| **transport_tsval**| UInt32 |
| **transport_tsecr**| UInt32 |
| **transport_spin**| boolean |
| **transport_cid**| UInt64 |
| **transport_pkn**| UInt64 |

## Application Layer Fields and Types

For some well-known application protocols, basic application information is captured. For non-encrypted traffic, session and sequence numbers are recorded, along with basic request/response decoding.  The currently supported application protocols include DNS, PING, HTTP, HTTPS and QUIC. For encrypted traffic (TLS), the Server Name Indicator (SNI) decoding is attempted:

| Column name | Column type |
|-------------|-------------|
| **e2e_sni**| string |
| **app_type**| category |
| **app_session**| category |
| **app_seq**| UInt64 |
| **app_request**| string |
| **app_response**| string |

## Not decoded data

By default, the E2EPacket class converts a binary packet into a decoded dictionary according to the above data schema. To enhance extensibility and flexibility, any data that is not decoded will be included in an additional field named **not_decoded_data** as a list of bytes. This field is passed to the first callback but will be removed before saving the result to the output file.
