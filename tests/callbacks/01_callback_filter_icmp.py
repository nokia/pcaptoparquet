import polars as pl


# Mandatory function: process_pcap_polars
def process_pcap_polars(df: pl.DataFrame) -> pl.DataFrame:
    """
    Filter ICMP and PING packets
    """
    return df.filter(
        (
            (pl.col("transport_type") == "ICMP")
            & ~(pl.col("ip_src").cast(pl.String).str.starts_with("127.0.0"))
            & ~(pl.col("ip_dst").cast(pl.String).str.starts_with("127.0.0"))
        )
    ).select(
        "num",
        "utc_date_time",
        "ip_src",
        "ip_dst",
        "transport_type",
        "app_type",
        "app_session",
        "app_seq",
        "app_request",
        "app_response",
    )
