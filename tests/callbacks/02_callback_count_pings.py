import polars as pl


# Mandatory function: process_pcap_polars
def process_pcap_polars(df: pl.DataFrame) -> pl.DataFrame:
    """
    Count PING requests...
    """
    return (
        df.filter(
            (
                (pl.col("app_type") == "PING")
                & (pl.col("app_request") != "")
                & (pl.col("app_response") == "")
            )
        )
        .group_by(["app_type"])
        .agg(pl.count("num").alias("ping_requests"))
    )
