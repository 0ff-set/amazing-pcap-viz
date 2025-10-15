from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional, Tuple, Iterable

import pandas as pd
from scapy.all import IP, IPv6, PcapReader, TCP, UDP


@dataclass(frozen=True)
class FlowKey:
    """Identifier for a network flow aggregated bidirectionally."""

    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str

    def normalized(self) -> "FlowKey":
        """Return a direction-agnostic key (sorted endpoints)."""
        left = (self.src_ip, self.src_port)
        right = (self.dst_ip, self.dst_port)
        if left <= right:
            return self
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )


@dataclass
class FilterOptions:
    include_ips: Optional[Iterable[str]] = None  # exact match list
    exclude_ips: Optional[Iterable[str]] = None
    protocols: Optional[Iterable[str]] = None  # e.g. {"TCP","UDP"}
    src_ports: Optional[Iterable[int]] = None
    dst_ports: Optional[Iterable[int]] = None
    time_start: Optional[pd.Timestamp] = None  # UTC
    time_end: Optional[pd.Timestamp] = None    # UTC


def _pass_filters(pkt_row: dict, opts: Optional[FilterOptions]) -> bool:
    if opts is None:
        return True

    ts = pd.to_datetime(pkt_row["timestamp"], unit="s", utc=True)
    src = pkt_row["src_ip"]
    dst = pkt_row["dst_ip"]
    proto = pkt_row["protocol"]
    sp = pkt_row["src_port"]
    dp = pkt_row["dst_port"]

    if opts.time_start is not None and ts < opts.time_start:
        return False
    if opts.time_end is not None and ts > opts.time_end:
        return False

    if opts.include_ips is not None and src not in opts.include_ips and dst not in opts.include_ips:
        return False
    if opts.exclude_ips is not None and (src in opts.exclude_ips or dst in opts.exclude_ips):
        return False

    if opts.protocols is not None and proto not in opts.protocols:
        return False

    if opts.src_ports is not None and sp is not None and sp not in opts.src_ports:
        return False
    if opts.dst_ports is not None and dp is not None and dp not in opts.dst_ports:
        return False

    return True


def _iter_packets(pcap_path: str, max_packets: Optional[int] = None, filters: Optional[FilterOptions] = None) -> Iterator[dict]:
    """Yield packet dicts from a PCAP.

    Keys: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, ip_version, ttl, tcp_flags
    """
    count = 0
    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            if max_packets is not None and count >= max_packets:
                break

            l3 = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if l3 is None:
                continue

            ip_version = 4 if l3.version == 4 else 6
            src_ip = l3.src
            dst_ip = l3.dst
            ttl = int(getattr(l3, "ttl", getattr(l3, "hlim", 0)))

            protocol = "OTHER"
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            tcp_flags_str: Optional[str] = None

            l4_tcp = pkt.getlayer(TCP)
            l4_udp = pkt.getlayer(UDP)
            if l4_tcp is not None:
                protocol = "TCP"
                src_port = int(l4_tcp.sport)
                dst_port = int(l4_tcp.dport)
                tcp_flags_str = l4_tcp.flags.flagrepr() if hasattr(l4_tcp.flags, "flagrepr") else str(l4_tcp.flags)
            elif l4_udp is not None:
                protocol = "UDP"
                src_port = int(l4_udp.sport)
                dst_port = int(l4_udp.dport)
            else:
                protocol = str(getattr(l3, "name", "OTHER")).upper()

            length = int(len(pkt))
            timestamp = float(pkt.time)

            row = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "ip_version": ip_version,
                "ttl": ttl,
                "tcp_flags": tcp_flags_str,
            }

            if not _pass_filters(row, filters):
                continue

            yield row
            count += 1


def parse_pcap(
    pcap_path: str,
    max_packets: Optional[int] = None,
    filters: Optional[FilterOptions] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Parse PCAP into packet and flow DataFrames.

    Returns (packets_df, flows_df)
    - packets_df: timestamp (datetime64[ns, UTC]), src_ip, dst_ip, src_port, dst_port, protocol, length, ip_version, ttl, tcp_flags
    - flows_df: src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, start_time, end_time, duration_s
    """
    rows = list(_iter_packets(pcap_path, max_packets=max_packets, filters=filters))
    if not rows:
        packets_df = pd.DataFrame(
            columns=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "length",
                "ip_version",
                "ttl",
                "tcp_flags",
            ]
        )
        flows_df = pd.DataFrame(
            columns=[
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "packets",
                "bytes",
                "start_time",
                "end_time",
                "duration_s",
            ]
        )
        return packets_df, flows_df

    packets_df = pd.DataFrame.from_records(rows)
    packets_df["timestamp"] = pd.to_datetime(packets_df["timestamp"], unit="s", utc=True)

    def keyify(row) -> Tuple[str, str, Optional[int], Optional[int], str]:
        key = FlowKey(
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
        ).normalized()
        return (
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.protocol,
        )

    packets_df["flow_key"] = packets_df.apply(keyify, axis=1)
    grouped = packets_df.groupby("flow_key")

    flows_df = grouped.agg(
        packets=("length", "count"),
        bytes=("length", "sum"),
        start_time=("timestamp", "min"),
        end_time=("timestamp", "max"),
    ).reset_index(names=["src_ip", "dst_ip", "src_port", "dst_port", "protocol"])
    flows_df["duration_s"] = (flows_df["end_time"] - flows_df["start_time"]).dt.total_seconds().clip(lower=0)

    return packets_df.drop(columns=["flow_key"]), flows_df
