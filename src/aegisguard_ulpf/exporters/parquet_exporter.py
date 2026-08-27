"""Optional Apache Parquet exporter; requires the local pyarrow package."""
from pathlib import Path
from aegisguard_ulpf.exporters.csv_exporter import _flatten
from aegisguard_ulpf.exporters.json_exporter import _payload

def export_parquet(events, output_path):
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("Parquet export requires the optional local dependency 'pyarrow'") from exc
    path = Path(output_path); path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist([_flatten(_payload(event)) for event in events]), path)
    return path
