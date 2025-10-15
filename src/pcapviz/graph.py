from __future__ import annotations

import networkx as nx
import pandas as pd
from pyvis.network import Network

CREDIT = "© 2025 JDRockfeller (Off-set)"


def build_host_graph(packets_df: pd.DataFrame, min_bytes: int = 0) -> nx.DiGraph:
    """Build a directed host conversation graph from packets.

    Nodes: IP addresses with attributes total_bytes, total_packets
    Edges: src->dst with attributes bytes, packets, protocol_weights
    """
    G = nx.DiGraph()
    if packets_df.empty:
        return G

    agg = (
        packets_df.groupby(["src_ip", "dst_ip", "protocol"]).agg(bytes=("length", "sum"), packets=("length", "count")).reset_index()
    )

    agg = agg[agg["bytes"] >= int(min_bytes)]

    node_bytes: dict[str, int] = {}
    node_packets: dict[str, int] = {}
    for _, row in agg.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]
        b = int(row["bytes"])
        p = int(row["packets"])
        node_bytes[src] = node_bytes.get(src, 0) + b
        node_packets[src] = node_packets.get(src, 0) + p
        node_bytes[dst] = node_bytes.get(dst, 0)
        node_packets[dst] = node_packets.get(dst, 0)

    for ip in set(list(agg["src_ip"]) + list(agg["dst_ip"])):
        G.add_node(ip, total_bytes=int(node_bytes.get(ip, 0)), total_packets=int(node_packets.get(ip, 0)))

    # combine per (src,dst) across protocols keeping weights
    edge_group = agg.groupby(["src_ip", "dst_ip"])  # mix protocols
    for (src, dst), df in edge_group:
        total_bytes = int(df["bytes"].sum())
        total_packets = int(df["packets"].sum())
        proto_weights = {str(r["protocol"]): int(r["bytes"]) for _, r in df.iterrows()}
        G.add_edge(src, dst, bytes=total_bytes, packets=total_packets, protocol_bytes=proto_weights)

    return G


def to_pyvis_html(G: nx.Graph, height: str = "700px", width: str = "100%", notebook: bool = False) -> str:
    """Render a NetworkX graph to a standalone HTML string via PyVis with protocol coloring and credit footer."""
    net = Network(height=height, width=width, notebook=notebook, directed=G.is_directed())

    for node, data in G.nodes(data=True):
        label = f"{node}\nbytes: {data.get('total_bytes', 0)}\npackets: {data.get('total_packets', 0)}"
        net.add_node(node, label=label, title=label)

    # simple color mapping by dominant protocol bytes
    proto_color = {"TCP": "#1f77b4", "UDP": "#ff7f0e", "OTHER": "#7f7f7f"}

    for u, v, data in G.edges(data=True):
        pbytes = data.get("protocol_bytes", {})
        dominant = max(pbytes, key=pbytes.get) if pbytes else "OTHER"
        color = proto_color.get(dominant, "#7f7f7f")
        label = f"{data.get('bytes', 0)} B / {data.get('packets', 0)} pkts\n{dominant}"
        net.add_edge(u, v, value=int(data.get("bytes", 0)), title=label, label=label, color=color)

    net.set_options(
        """
        var options = {
            nodes: { shape: 'dot', scaling: { min: 5, max: 30 } },
            edges: { arrows: { to: { enabled: true } }, smooth: { type: 'dynamic' } },
            physics: { stabilization: true }
        };
        """
    )

    html = net.generate_html()
    # add credit footer
    footer = f"<div style=\"text-align:center;color:#888;font-size:12px;margin-top:4px\">{CREDIT}</div>"
    return html + footer


def export_graphml(G: nx.Graph, path: str) -> None:
    nx.write_graphml(G, path)
