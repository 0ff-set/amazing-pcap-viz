from __future__ import annotations

import pandas as pd


def compute_top_talkers(packets_df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Return top n IPs by total bytes sent+received."""
    if packets_df.empty:
        return pd.DataFrame(columns=["ip", "bytes", "packets"])

    by_src = (
        packets_df.groupby("src_ip").agg(bytes=("length", "sum"), packets=("length", "count")).rename_axis("ip")
    )
    by_dst = (
        packets_df.groupby("dst_ip").agg(bytes=("length", "sum"), packets=("length", "count")).rename_axis("ip")
    )
    total = by_src.add(by_dst, fill_value=0).sort_values("bytes", ascending=False)
    return total.reset_index().head(n)


def compute_top_ports(packets_df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Return top n destination ports by bytes, separately for TCP and UDP."""
    if packets_df.empty:
        return pd.DataFrame(columns=["protocol", "port", "bytes", "packets"])

    df = packets_df.copy()
    df = df[df["dst_port"].notna()]
    df["dst_port"] = df["dst_port"].astype(int)
    agg = (
        df.groupby(["protocol", "dst_port"]).agg(bytes=("length", "sum"), packets=("length", "count"))
        .sort_values("bytes", ascending=False)
        .reset_index()
    )
    return agg.groupby("protocol").head(n).reset_index(drop=True)


def compute_protocol_breakdown(packets_df: pd.DataFrame) -> pd.DataFrame:
    """Return bytes and packets by protocol."""
    if packets_df.empty:
        return pd.DataFrame(columns=["protocol", "bytes", "packets"])

    return (
        packets_df.groupby("protocol")
        .agg(bytes=("length", "sum"), packets=("length", "count"))
        .sort_values("bytes", ascending=False)
        .reset_index()
    )


def compute_throughput(packets_df: pd.DataFrame, rule: str = "1S") -> pd.DataFrame:
    """Compute throughput over time using pandas resample rule (e.g., '1S', '100ms')."""
    if packets_df.empty:
        return pd.DataFrame(columns=["timestamp", "bytes", "packets"])

    series = packets_df.set_index("timestamp").sort_index()
    res = series["length"].resample(rule).agg(["sum", "count"]).rename(
        columns={"sum": "bytes", "count": "packets"}
    )
    res = res.reset_index().rename(columns={"index": "timestamp"})
    return res


def compute_conversation_matrix(packets_df: pd.DataFrame) -> pd.DataFrame:
    """Return a pivot table (IP x IP) with total bytes from src to dst."""
    if packets_df.empty:
        return pd.DataFrame()
    pivot = (
        packets_df.pivot_table(index="src_ip", columns="dst_ip", values="length", aggfunc="sum", fill_value=0)
    )
    return pivot
