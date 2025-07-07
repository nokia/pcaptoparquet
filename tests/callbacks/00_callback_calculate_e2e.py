"""
Calculate end-to-end fields for a Polars DataFrame containing packet data.
"""

import polars as pl

# "e2e_link": "string",
# "e2e_ip_client": "category",
# "e2e_ip_server": "category",
# "e2e_ip_pair": "string",
# "e2e_stream": "string",

# def calculate_e2e_fields(self) -> None:
#     """
#     Calculate the end-to-end fields of a packet.
#     """
#     # E2E Link
#     if self.eth_src is not None and self.eth_dst is not None:
#         if self.eth_src < self.eth_dst:
#             self.e2e_link = str(self.eth_src) + "_" + str(self.eth_dst)
#         else:
#             self.e2e_link = str(self.eth_dst) + "_" + str(self.eth_src)

#     # E2E IP Pair
#     if self.ip_src < self.ip_dst:
#         self.e2e_ip_pair = str(self.ip_src) + "_" + str(self.ip_dst)
#     else:
#         self.e2e_ip_pair = str(self.ip_dst) + "_" + str(self.ip_src)

#     # E2E IP Client
#     # E2E IP Server
#     # E2E Stream
#     if self.transport_src_port is not None and self.transport_dst_port is not None:
#         if self.transport_src_port < 1024 and self.transport_dst_port > 1023:
#             self.ip_client = self.ip_dst
#             self.ip_server = self.ip_src

#         if self.transport_src_port > 1023 and self.transport_dst_port < 1024:
#             self.ip_client = self.ip_src
#             self.ip_server = self.ip_dst

#         if self.ip_src < self.ip_dst:
#             self.stream = (
#                 str(self.transport_type).lower()
#                 + "_"
#                 + str(self.ip_src)
#                 + "_"
#                 + str(self.transport_src_port)
#                 + "_"
#                 + str(self.ip_dst)
#                 + "_"
#                 + str(self.transport_dst_port)
#             )
#         else:
#             self.stream = (
#                 str(self.transport_type).lower()
#                 + "_"
#                 + str(self.ip_dst)
#                 + "_"
#                 + str(self.transport_dst_port)
#                 + "_"
#                 + str(self.ip_src)
#                 + "_"
#                 + str(self.transport_src_port)
#             )

#     else:
#         self.stream = str(self.transport_type).lower() + "_" + self.e2e_ip_pair

#     # Add CID to stream if it exists
#     if self.transport_cid is not None:
#         self.stream = self.stream + "_" + str(self.transport_cid)


# Mandatory function: process_pcap_polars
def process_pcap_polars(df: pl.DataFrame) -> pl.DataFrame:
    """
    Calculate end-to-end fields for a Polars DataFrame containing packet data.
    """
    # E2E Link
    df = df.with_columns(
        pl.when(pl.col("eth_src").cast(pl.Utf8) < pl.col("eth_dst").cast(pl.Utf8))
        .then(
            pl.concat_str(
                [
                    pl.col("eth_src").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("eth_dst").cast(pl.Utf8),
                ]
            )
        )
        .otherwise(
            pl.concat_str(
                [
                    pl.col("eth_dst").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("eth_src").cast(pl.Utf8),
                ]
            )
        )
        .alias("e2e_link")
    ).with_columns(
        pl.when(pl.col("e2e_link") == pl.lit("_"))
        .then(pl.lit(None).cast(pl.Utf8))
        .otherwise(pl.col("e2e_link"))
        .alias("e2e_link")
    )

    # E2E IP Pair
    df = df.with_columns(
        pl.when(pl.col("ip_src").cast(pl.Utf8) < pl.col("ip_dst").cast(pl.Utf8))
        .then(
            pl.concat_str(
                [
                    pl.col("ip_src").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("ip_dst").cast(pl.Utf8),
                ]
            )
        )
        .otherwise(
            pl.concat_str(
                [
                    pl.col("ip_dst").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("ip_src").cast(pl.Utf8),
                ]
            )
        )
        .alias("e2e_ip_pair")
    )

    # E2E IP Client and Server
    df = df.with_columns(
        pl.when(
            (pl.col("transport_src_port") < 1024)
            & (pl.col("transport_dst_port") > 1023)
        )
        .then(pl.col("ip_dst").cast(pl.Utf8))
        .otherwise(pl.col("ip_src").cast(pl.Utf8))
        .alias("e2e_ip_client")
    ).with_columns(
        pl.when(
            (pl.col("transport_src_port") < 1024)
            & (pl.col("transport_dst_port") > 1023)
        )
        .then(pl.col("ip_src").cast(pl.Utf8))
        .otherwise(pl.col("ip_dst").cast(pl.Utf8))
        .alias("e2e_ip_server")
    )

    # E2E Stream
    df = df.with_columns(
        pl.when(pl.col("transport_src_port") < pl.col("transport_dst_port"))
        .then(
            pl.concat_str(
                [
                    pl.col("transport_type").cast(pl.Utf8).str.to_lowercase(),
                    pl.lit("_"),
                    pl.col("ip_src").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("transport_src_port").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("ip_dst").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("transport_dst_port").cast(pl.Utf8),
                ]
            )
        )
        .otherwise(
            pl.concat_str(
                [
                    pl.col("transport_type").cast(pl.Utf8).str.to_lowercase(),
                    pl.lit("_"),
                    pl.col("ip_dst").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("transport_dst_port").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("ip_src").cast(pl.Utf8),
                    pl.lit("_"),
                    pl.col("transport_src_port").cast(pl.Utf8),
                ]
            )
        )
        .alias("e2e_stream")
    )
    # Add CID to stream if it exists
    df = df.with_columns(
        pl.when(pl.col("transport_cid").is_not_null())
        .then(
            pl.concat_str(
                [
                    pl.col("e2e_stream"),
                    pl.lit("_"),
                    pl.col("transport_cid").cast(pl.Utf8),
                ]
            )
        )
        .otherwise(pl.col("e2e_stream"))
        .alias("e2e_stream")
    )
    # Convert IP columns to category type
    df = df.with_columns(
        pl.col("e2e_ip_client").cast(pl.Categorical),
        pl.col("e2e_ip_server").cast(pl.Categorical),
    )
    return df
