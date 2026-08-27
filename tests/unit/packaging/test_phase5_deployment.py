from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def test_compose_runs_only_a_network_isolated_ulpf_runtime():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ulpf-runtime:" in compose
    assert "network_mode: none" in compose
    assert "demo/run_demo.py" in compose
    assert not any(name in compose for name in ("dashboard:", "database:", "analyzer:"))

def test_container_and_airgap_documentation_reference_existing_local_workflows():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY demo ./demo" in dockerfile
    assert "--no-index --find-links=/wheelhouse" in dockerfile
    assert "docker compose up" in (ROOT / "docs" / "container_deployment.md").read_text(encoding="utf-8")
