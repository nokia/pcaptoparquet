"""
Functional tests for pcap to parquet conversion
"""

import os

from pcaptoparquet import E2EConfig

from .test_utils import configure_dirs, generate_outputs

# # Test errors...
# def test_error() -> None:
#     """Test error cases..."""
#     dirs = configure_dirs()
#     ddir = os.path.join(dirs["ddir"])
#     odir = os.path.join(dirs["odir"])
#     input_file = os.path.join(ddir, "error_quic.pcap")
#     generate_outputs(input_file, E2EConfig(), "Client", odir, parallel=False)


# 00_file_formats/00_raw_ipv4_network_2MB.pcap
def test_raw_ipv4_network_2mb_pcap() -> None:
    """Test the raw_ipv4_network_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "00_file_formats")
    odir = os.path.join(dirs["odir"], "00_functional", "00_file_formats")
    input_file = os.path.join(ddir, "00_raw_ipv4_network_2MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 00_file_formats/01_raw_ipv4_network_2MB.pcapng
def test_raw_ipv4_network_2mb_pcapng() -> None:
    """Test the raw_ipv4_network_2MB.pcapng file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "00_file_formats")
    odir = os.path.join(dirs["odir"], "00_functional", "00_file_formats")
    input_file = os.path.join(ddir, "01_raw_ipv4_network_2MB.pcapng.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 00_file_formats/10_raw_ipv4_client_10MB.pcap
def test_raw_ipv4_client_10mb_pcap() -> None:
    """Test the raw_ipv4_client_10MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "00_file_formats")
    odir = os.path.join(dirs["odir"], "00_functional", "00_file_formats")
    input_file = os.path.join(ddir, "10_raw_ipv4_client_10MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 00_file_formats/11_raw_ipv4_client_10MB.pcapng
def test_raw_ipv4_client_10mb_pcapng() -> None:
    """Test the raw_ipv4_client_10MB.pcapng file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "00_file_formats")
    odir = os.path.join(dirs["odir"], "00_functional", "00_file_formats")
    input_file = os.path.join(ddir, "11_raw_ipv4_client_10MB.pcapng.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 01_encapsulations/00_null_ipv4_Network_2MB.pcap
def test_null_ipv4_network_2mb_pcap() -> None:
    """Test the null_ipv4_Network_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "01_encapsulations")
    odir = os.path.join(dirs["odir"], "00_functional", "01_encapsulations")
    input_file = os.path.join(ddir, "00_null_ipv4_Network_2MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 01_encapsulations/10_sll_ipv4_Client_500KB.pcap
def test_sll_ipv4_client_500kb_pcap() -> None:
    """Test the sll_ipv4_Client_500KB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "01_encapsulations")
    odir = os.path.join(dirs["odir"], "00_functional", "01_encapsulations")
    input_file = os.path.join(ddir, "10_sll_ipv4_Client_500KB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 01_encapsulations/20_eth_802.1q_ipv4_Network_2MB.pcap
def test_eth_802_1q_ipv4_network_2mb_pcap() -> None:
    """Test the eth_802.1q_ipv4_Network_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "01_encapsulations")
    odir = os.path.join(dirs["odir"], "00_functional", "01_encapsulations")
    input_file = os.path.join(ddir, "20_eth_802.1q_ipv4_Network_2MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 01_encapsulations/99_sll_unknown.pcap
def test_sll_unknown_pcap() -> None:
    """Test the sll_unknown.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "01_encapsulations")
    odir = os.path.join(dirs["odir"], "00_functional", "01_encapsulations")
    input_file = os.path.join(ddir, "99_sll_unknown.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 02_tunels/00_eth_802.1q_ipv4_udp_gtp_ipv4_network_5MB.pcap
def test_eth_802_1q_ipv4_udp_gtp_ipv4_network_5mb_pcap() -> None:
    """Test the eth_802.1q_ipv4_udp_gtp_ipv4_network_5MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "02_tunels")
    odir = os.path.join(dirs["odir"], "00_functional", "02_tunels")
    input_file = os.path.join(
        ddir, "00_eth_802.1q_ipv4_udp_gtp_ipv4_network_5MB.pcap.gz"
    )
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 02_tunels/01_eth_802.1q_ipv4_udp_gtp_ipv6_2MB.pcap
def test_eth_802_1q_ipv4_udp_gtp_ipv6_2mb_pcap() -> None:
    """Test the eth_802.1q_ipv4_udp_gtp_ipv6_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "02_tunels")
    odir = os.path.join(dirs["odir"], "00_functional", "02_tunels")
    input_file = os.path.join(ddir, "01_eth_802.1q_ipv4_udp_gtp_ipv6_2MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 02_tunels/02_eth_mpls_ipv4_udp_gtp_ipv4_5MB.pcap
def test_eth_mpls_ipv4_udp_gtp_ipv4_5mb_pcap() -> None:
    """Test the eth_mpls_ipv4_udp_gtp_ipv4_5MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "02_tunels")
    odir = os.path.join(dirs["odir"], "00_functional", "02_tunels")
    input_file = os.path.join(ddir, "02_eth_mpls_ipv4_udp_gtp_ipv4_5MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 02_tunels/03_null_ipv4_udp_gtp_ipv4_udp_vxlan_eth_ipv4_2MB.pcap
def test_null_ipv4_udp_gtp_ipv4_udp_vxlan_eth_ipv4_2mb_pcap() -> None:
    """Test the null_ipv4_udp_gtp_ipv4_udp_vxlan_eth_ipv4_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "02_tunels")
    odir = os.path.join(dirs["odir"], "00_functional", "02_tunels")
    input_file = os.path.join(
        ddir, "03_null_ipv4_udp_gtp_ipv4_udp_vxlan_eth_ipv4_2MB.pcap.gz"
    )
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 03_ip_versions/00_sll_eth_ipv4_Client_500KB.pcap
def test_sll_eth_ipv4_client_500kb_pcap() -> None:
    """Test the sll_eth_ipv4_Client_500KB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(ddir, "00_sll_eth_ipv4_Client_500KB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 03_ip_versions/01_raw_ipv4_udp_gtp_ipv4_Network_2MB.pcapng
def test_raw_ipv4_udp_gtp_ipv4_network_2mb_pcapng() -> None:
    """Test the raw_ipv4_udp_gtp_ipv4_Network_2MB.pcapng file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(ddir, "01_raw_ipv4_udp_gtp_ipv4_Network_2MB.pcapng.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 03_ip_versions/10_sll_eth_ipv6_Client_1MB.pcap
def test_sll_eth_ipv6_client_1mb_pcap() -> None:
    """Test the sll_eth_ipv6_Client_1MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(ddir, "10_sll_eth_ipv6_Client_1MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 03_ip_versions/11_eth_802.1q_ipv6_Network_2MB.pcap
def test_eth_802_1q_ipv6_network_2mb_pcap() -> None:
    """Test the eth_802.1q_ipv6_Network_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(ddir, "11_eth_802.1q_ipv6_Network_2MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 03_ip_versions/12_eth_mpls_ipv6_Network_10MB.pcap
def test_eth_mpls_ipv6_network_10mb_pcap() -> None:
    """Test the eth_mpls_ipv6_Network_10MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(ddir, "12_eth_mpls_ipv6_Network_10MB.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 03_ip_versions/20_eth_802.1q_ipv4_udp_gtp_ipv6_Network_2MB.pcap
def test_eth_802_1q_ipv4_udp_gtp_ipv6_network_2mb_pcap() -> None:
    """Test the eth_802.1q_ipv4_udp_gtp_ipv6_Network_2MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(
        ddir, "20_eth_802.1q_ipv4_udp_gtp_ipv6_Network_2MB.pcap.gz"
    )
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 03_ip_versions/21_eth_mpls_ipv4_udp_gtp_ipv6_Network_10MB.pcap
def test_eth_mpls_ipv4_udp_gtp_ipv6_network_10mb_pcap() -> None:
    """Test the eth_mpls_ipv4_udp_gtp_ipv6_Network_10MB.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "03_ip_versions")
    odir = os.path.join(dirs["odir"], "00_functional", "03_ip_versions")
    input_file = os.path.join(
        ddir, "21_eth_mpls_ipv4_udp_gtp_ipv6_Network_10MB.pcap.gz"
    )
    generate_outputs(input_file, E2EConfig(), "Network", odir)


# 04_transports/00_udp_volte.pcap
def test_udp_volte_pcap() -> None:
    """Test the udp_volte.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "00_udp_volte.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 04_transports/01_udp_voice_ott.pcap
def test_udp_voice_ott_pcap() -> None:
    """Test the udp_voice_ott.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "01_udp_voice_ott.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 04_transports/10_tcp_volte.pcap
def test_tcp_volte_pcap() -> None:
    """Test the tcp_volte.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "10_tcp_volte.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 04_transports/11_tcp_voice_ott.pcap
def test_tcp_voice_ott_pcap() -> None:
    """Test the tcp_voice_ott.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "11_tcp_voice_ott.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 04_transports/12_tcp_ookla_ping.pcap
def test_tcp_ookla_ping_pcap() -> None:
    """Test the tcp_ookla_ping.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "12_tcp_ookla_ping.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 04_transports/20_udp_gquic.pcap
def test_udp_gquic_pcap() -> None:
    """Test the udp_gquic.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "20_udp_gquic.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 04_transports/21_udp_ietf_quic.pcap
def test_udp_ietf_quic_pcap() -> None:
    """Test the udp_ietf_quic.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "21_udp_ietf_quic.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 04_transports/30_sctp.pcapng
def test_sctp_pcapng() -> None:
    """Test the sctp.pcapng file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "04_transports")
    odir = os.path.join(dirs["odir"], "00_functional", "04_transports")
    input_file = os.path.join(ddir, "30_sctp.pcapng.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/00_dns.pcap
def test_dns_pcap() -> None:
    """Test the dns.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "00_dns.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/01_icmp.pcap
def test_icmp_pcap() -> None:
    """Test the icmp.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "01_icmp.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/10_http.pcap
def test_http_pcap() -> None:
    """Test the http.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "10_http.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/11_http_GET.pcap
def test_http_get_pcap() -> None:
    """Test the http_GET.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "11_http_GET.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/12_http_200OK.pcap
def test_http_200ok_pcap() -> None:
    """Test the http_200OK.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "12_http_200OK.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/12_http_POST.pcap
def test_http_post_pcap() -> None:
    """Test the http_POST.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "12_http_POST.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/20_https.pcap
def test_https_pcap() -> None:
    """Test the https.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "20_https.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/30.gquic.pcap
def test_gquic_pcap() -> None:
    """Test the https.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "30.gquic.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/31.ietf_quic_draft29.pcap
def test_ietf_quic_draft29_pcap() -> None:
    """Test the https.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "31.ietf_quic_draft29.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/32.ietf_quic_v1.pcap
def test_ietf_quic_v1_pcap() -> None:
    """Test the https.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "32.ietf_quic_v1.pcap.gz")
    generate_outputs(input_file, E2EConfig(), "Client", odir)


# 05_applications/50_sip_ott.pcap
def test_sip_ott_pcap() -> None:
    """Test the sip_ott.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "50_sip_ott.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 05_applications/51_esp_sip.pcapng
def test_esp_sip_pcapng() -> None:
    """Test the esp_sip.pcapng file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "51_esp_sip.pcapng.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 05_applications/52_rtp.pcap
def test_rtp_pcap() -> None:
    """Test the rtp.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "52_rtp.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 05_applications/53_rtcp.pcap
def test_rtcp_pcap() -> None:
    """Test the rtcp.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "53_rtcp.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 05_applications/60_stun.pcap
def test_stun_pcap() -> None:
    """Test the stun.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "60_stun.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "volte.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


# 05_applications/99.twamp.pcap
def test_twamp_pcap() -> None:
    """Test the twamp.pcap file"""
    dirs = configure_dirs()
    ddir = os.path.join(dirs["ddir"], "00_functional", "05_applications")
    odir = os.path.join(dirs["odir"], "00_functional", "05_applications")
    input_file = os.path.join(ddir, "99.twamp.pcap.gz")
    configpath = os.path.join(dirs["cdir"], "twamplight.cfg")
    generate_outputs(input_file, E2EConfig(configpath=configpath), "Client", odir)


if __name__ == "__main__":

    test_raw_ipv4_network_2mb_pcap()
    test_raw_ipv4_network_2mb_pcapng()
    test_raw_ipv4_client_10mb_pcap()
    test_raw_ipv4_client_10mb_pcapng()
    test_null_ipv4_network_2mb_pcap()
    test_sll_ipv4_client_500kb_pcap()
    test_eth_802_1q_ipv4_network_2mb_pcap()
    test_eth_802_1q_ipv4_udp_gtp_ipv4_network_5mb_pcap()
    test_eth_802_1q_ipv4_udp_gtp_ipv6_2mb_pcap()
    test_eth_mpls_ipv4_udp_gtp_ipv4_5mb_pcap()
    test_null_ipv4_udp_gtp_ipv4_udp_vxlan_eth_ipv4_2mb_pcap()
    test_sll_eth_ipv4_client_500kb_pcap()
    test_raw_ipv4_udp_gtp_ipv4_network_2mb_pcapng()
    test_sll_eth_ipv6_client_1mb_pcap()
    test_eth_802_1q_ipv6_network_2mb_pcap()
    test_eth_mpls_ipv6_network_10mb_pcap()
    test_eth_802_1q_ipv4_udp_gtp_ipv6_network_2mb_pcap()
    test_eth_mpls_ipv4_udp_gtp_ipv6_network_10mb_pcap()
    test_udp_volte_pcap()
    test_udp_voice_ott_pcap()
    test_tcp_volte_pcap()
    test_tcp_voice_ott_pcap()
    test_tcp_ookla_ping_pcap()
    test_udp_gquic_pcap()
    test_udp_ietf_quic_pcap()
    test_sctp_pcapng()
    test_dns_pcap()
    test_icmp_pcap()
    test_http_pcap()
    test_http_get_pcap()
    test_http_200ok_pcap()
    test_http_post_pcap()
    test_https_pcap()
    test_sip_ott_pcap()
    test_esp_sip_pcapng()
    test_rtp_pcap()
    test_rtcp_pcap()
    test_stun_pcap()
    test_twamp_pcap()

    print("All tests passed!")
