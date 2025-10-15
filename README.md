# PCAPViz

Advanced PCAP parsing and visualization: filters, metrics, graphs, CSV and GraphML export, and a Streamlit web UI.

## Features
- Packet and flow parsing (IPv4/IPv6, TCP/UDP; others as OTHER)
- Filters: include/exclude IPs, protocols, src/dst ports, time range
- Extra packet fields: `ip_version`, `ttl/hlim`, `tcp_flags`
- Metrics: top talkers, protocol breakdown, throughput (resample), top ports, conversation matrix
- Graphs: host conversation graph with dominant protocol coloring; HTML (PyVis) and GraphML export
- UI: Streamlit app with interactive charts and CSV downloads
- CLI: batch export to CSV/HTML/GraphML with filters

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Streamlit App

```bash
streamlit run app_streamlit.py
```

Upload `.pcap`/`.pcapng`, apply filters (IPs, ports, protocols, time), explore metrics and graphs, and download CSV/GraphML.

## CLI

```bash
python -m src.pcapviz.cli sample.pcap \
  --out-dir out \
  --max-packets 0 \
  --throughput 1S \
  --min-bytes 0 \
  --include-ips 10.0.0.1 10.0.0.2 \
  --protocols TCP UDP \
  --src-ports 80 443 \
  --dst-ports 53 \
  --start 2024-01-01T00:00:00Z \
  --end 2024-01-01T23:59:59Z
```

Outputs: `packets.csv`, `flows.csv`, `top_talkers.csv`, `protocols.csv`, `throughput.csv`, `top_ports.csv`, `graph.html`, `graph.graphml`.

## Modules
- `src/pcapviz/parser.py`: parsing with filters; extra fields `ip_version`, `ttl/hlim`, `tcp_flags`
- `src/pcapviz/metrics.py`: top talkers, protocols, throughput, top ports, conversation matrix
- `src/pcapviz/graph.py`: graph with dominant protocol coloring, GraphML export, HTML footer
## Credits
© 2025 JDRockfeller (Off-set)
