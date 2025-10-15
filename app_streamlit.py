import io
import json
import streamlit as st
import pandas as pd

from src.pcapviz.parser import parse_pcap, FilterOptions
from src.pcapviz.metrics import (
    compute_top_talkers,
    compute_protocol_breakdown,
    compute_throughput,
    compute_top_ports,
    compute_conversation_matrix,
)
from src.pcapviz.graph import build_host_graph, to_pyvis_html, export_graphml

st.set_page_config(page_title="PCAPViz — JDRockfeller (Off-set)", layout="wide")

st.title("PCAPViz: Анализ и визуализация PCAP")
st.caption("© 2025 JDRockfeller (Off-set)")

uploaded = st.file_uploader("Загрузите PCAP-файл", type=["pcap", "pcapng"]) 
max_packets = st.number_input("Ограничение пакетов (0 = без лимита)", min_value=0, value=0, step=1000)

with st.expander("Фильтры"):
    ips = st.text_input("Включить IP (через запятую)")
    exclude_ips = st.text_input("Исключить IP (через запятую)")
    protos = st.multiselect("Протоколы", ["TCP", "UDP", "OTHER"], default=[])
    src_ports = st.text_input("SRC порты (через запятую)")
    dst_ports = st.text_input("DST порты (через запятую)")
    tstart = st.text_input("Начало (UTC, ISO, опционально)")
    tend = st.text_input("Конец (UTC, ISO, опционально)")

    def parse_list_int(txt: str):
        return [int(x.strip()) for x in txt.split(",") if x.strip().isdigit()] if txt.strip() else None

    def parse_list_str(txt: str):
        return [x.strip() for x in txt.split(",") if x.strip()] if txt.strip() else None

    start_ts = pd.to_datetime(tstart, utc=True) if tstart.strip() else None
    end_ts = pd.to_datetime(tend, utc=True) if tend.strip() else None

    filter_opts = FilterOptions(
        include_ips=parse_list_str(ips),
        exclude_ips=parse_list_str(exclude_ips),
        protocols=protos if protos else None,
        src_ports=parse_list_int(src_ports),
        dst_ports=parse_list_int(dst_ports),
        time_start=start_ts,
        time_end=end_ts,
    )

if uploaded is not None:
    tmp_bytes = uploaded.read()
    with open(".tmp_upload.pcap", "wb") as f:
        f.write(tmp_bytes)

    packets_df, flows_df = parse_pcap(
        ".tmp_upload.pcap",
        max_packets=(None if max_packets == 0 else max_packets),
        filters=filter_opts,
    )

    st.subheader("Сводка")
    st.write({
        "Пакетов": int(len(packets_df)),
        "Флоу": int(len(flows_df)),
        "Временной диапазон": (
            f"{packets_df['timestamp'].min()} — {packets_df['timestamp'].max()}" if not packets_df.empty else "—"
        ),
        "Всего байт": int(packets_df["length"].sum()) if not packets_df.empty else 0,
    })

    with st.expander("Пакеты"):
        st.dataframe(packets_df.head(2000))
        if not packets_df.empty:
            st.download_button("Скачать packets.csv", packets_df.to_csv(index=False).encode("utf-8"), "packets.csv")

    with st.expander("Флоу"):
        st.dataframe(flows_df.head(2000))
        if not flows_df.empty:
            st.download_button("Скачать flows.csv", flows_df.to_csv(index=False).encode("utf-8"), "flows.csv")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Топ узлы")
        top = compute_top_talkers(packets_df, n=15)
        st.dataframe(top)
        if not top.empty:
            st.download_button("Скачать top_talkers.csv", top.to_csv(index=False).encode("utf-8"), "top_talkers.csv")

    with col2:
        st.subheader("Протоколы")
        proto = compute_protocol_breakdown(packets_df)
        st.dataframe(proto)
        if not proto.empty:
            st.download_button("Скачать protocols.csv", proto.to_csv(index=False).encode("utf-8"), "protocols.csv")

    st.subheader("Топ порты (DST)")
    ports = compute_top_ports(packets_df, n=15)
    st.dataframe(ports)

    st.subheader("Пропускная способность")
    rule = st.selectbox("Интервал", ["500ms", "1S", "5S", "10S", "1min"], index=1)
    thr = compute_throughput(packets_df, rule=rule)
    st.line_chart(thr.set_index("timestamp")["bytes"])  # bytes per bucket
    if not thr.empty:
        st.download_button("Скачать throughput.csv", thr.to_csv(index=False).encode("utf-8"), "throughput.csv")

    st.subheader("Матрица разговоров")
    conv = compute_conversation_matrix(packets_df)
    if not conv.empty:
        st.dataframe(conv)

    st.subheader("Граф узлов")
    min_bytes = st.slider(
        "Минимум байт на ребро",
        min_value=0,
        max_value=int(max(1, packets_df["length"].sum() // 10)),
        value=0,
    )
    G = build_host_graph(packets_df, min_bytes=min_bytes)
    html = to_pyvis_html(G)
    st.components.v1.html(html, height=720, scrolling=True)
    if G.number_of_edges() > 0:
        export_graphml(G, ".tmp_graph.graphml")
        with open(".tmp_graph.graphml", "rb") as fh:
            st.download_button("Скачать graph.graphml", fh, file_name="graph.graphml")
else:
    st.info("Загрузите PCAP для начала анализа.")
