# ULPF Runtime Container

The container runs only the AegisGuard-ULPF preprocessing demo. It does not
start a SIEM, database, dashboard, analyzer, or external service.

```powershell
docker compose up --build
```

The `ulpf-runtime` service runs with `network_mode: none`, processes the
bundled local demo input, and writes JSONL files to `demo/output/` through the
mounted output volume. The evidence volume persists the raw hash-chain store.

For an air-gapped host, build/export the image on a connected preparation host
first, verify the transferred bundle, load it locally, then run:

```powershell
docker compose up
```
