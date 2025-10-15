# PCAPViz

Инструмент для продвинутого парсинга и визуализации PCAP: фильтры, метрики, графы, экспорт.

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск Streamlit-приложения

```bash
streamlit run app_streamlit.py
```

Загрузите `.pcap`/`.pcapng`, примените фильтры (IP, порты, протоколы, диапазон времени), изучайте метрики, граф, пропускную способность и выгружайте CSV/GraphML.

## CLI — © 2025 JDRockfeller (Off-set)

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

Выходные файлы: `packets.csv`, `flows.csv`, `top_talkers.csv`, `protocols.csv`, `throughput.csv`, `top_ports.csv`, `graph.html`, `graph.graphml`.

## Модули
- `src/pcapviz/parser.py`: чтение PCAP с фильтрами; дополнительные поля `ip_version`, `ttl/hlim`, `tcp_flags`.
- `src/pcapviz/metrics.py`: топ говорящие, протоколы, пропускная способность, топ порты, матрица разговоров.
- `src/pcapviz/graph.py`: граф с доминирующим протоколом на ребре, экспорт GraphML, HTML с футером «© 2025 JDRockfeller (Off-set)».

© 2025 JDRockfeller (Off-set)
