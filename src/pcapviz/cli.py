from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from .parser import parse_pcap, FilterOptions
from .metrics import compute_top_talkers, compute_protocol_breakdown, compute_throughput, compute_top_ports
from .graph import build_host_graph, to_pyvis_html, export_graphml

CREDIT = "© 2025 JDRockfeller (Off-set)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"PCAP parser and visualizer — {CREDIT}")
    parser.add_argument("pcap", help="Path to pcap/pcapng file")
    parser.add_argument("--max-packets", type=int, default=0, help="Limit packets parsed (0 = no limit)")
    parser.add_argument("--out-dir", type=Path, default=Path("out"), help="Output directory")
    parser.add_argument("--throughput", default="1S", help="Resample rule for throughput")
    parser.add_argument("--min-bytes", type=int, default=0, help="Min bytes threshold for edges in graph")
    parser.add_argument("--include-ips", nargs="*", help="Only include traffic where src or dst in list")
    parser.add_argument("--exclude-ips", nargs="*", help="Exclude traffic where src or dst in list")
    parser.add_argument("--protocols", nargs="*", help="Filter protocols, e.g., TCP UDP")
    parser.add_argument("--src-ports", nargs="*", type=int, help="Filter by source ports")
    parser.add_argument("--dst-ports", nargs="*", type=int, help="Filter by destination ports")
    parser.add_argument("--start", help="Start time (UTC ISO)")
    parser.add_argument("--end", help="End time (UTC ISO)")

    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    start_ts = pd.to_datetime(args.start, utc=True) if args.start else None
    end_ts = pd.to_datetime(args.end, utc=True) if args.end else None

    filters = FilterOptions(
        include_ips=args.include_ips,
        exclude_ips=args.exclude_ips,
        protocols=args.protocols,
        src_ports=args.src_ports,
        dst_ports=args.dst_ports,
        time_start=start_ts,
        time_end=end_ts,
    )

    packets_df, flows_df = parse_pcap(
        str(args.pcap),
        max_packets=(None if args.max_packets == 0 else args.max_packets),
        filters=filters,
    )

    packets_csv = args.out_dir / "packets.csv"
    flows_csv = args.out_dir / "flows.csv"
    packets_df.to_csv(packets_csv, index=False)
    flows_df.to_csv(flows_csv, index=False)

    top_csv = args.out_dir / "top_talkers.csv"
    proto_csv = args.out_dir / "protocols.csv"
    thr_csv = args.out_dir / "throughput.csv"
    ports_csv = args.out_dir / "top_ports.csv"
    compute_top_talkers(packets_df).to_csv(top_csv, index=False)
    compute_protocol_breakdown(packets_df).to_csv(proto_csv, index=False)
    compute_throughput(packets_df, rule=args.throughput).to_csv(thr_csv, index=False)
    compute_top_ports(packets_df).to_csv(ports_csv, index=False)

    G = build_host_graph(packets_df, min_bytes=args.min_bytes)
    html = to_pyvis_html(G)
    (args.out_dir / "graph.html").write_text(html, encoding="utf-8")
    export_graphml(G, str(args.out_dir / "graph.graphml"))

    print(CREDIT, file=sys.stderr)
    print(
        f"Wrote: {packets_csv}, {flows_csv}, {top_csv}, {proto_csv}, {thr_csv}, {ports_csv}, graph.html, graph.graphml",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
