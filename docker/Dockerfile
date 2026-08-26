FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml ./
COPY src ./src

RUN python -m pip wheel --wheel-dir /wheelhouse .


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /wheelhouse /wheelhouse

RUN python -m pip install --no-index --find-links=/wheelhouse aegisguard-ulpf \
    && rm -rf /wheelhouse \
    && addgroup --system aegisguard \
    && adduser --system --ingroup aegisguard aegisguard

RUN python -c "from importlib.resources import files; from aegisguard_ulpf.parsing.semantic_packs.loader import load_semantic_pack; root = files('aegisguard_ulpf.parsing.semantic_packs'); packs = root.joinpath('packs'); keys = root.joinpath('trusted_keys'); assert {'aegisguard-dev-v1.pem', 'aegisguard-dev-v2.pem', 'aegisguard-dev-v3.pem'} <= {key.name for key in keys.iterdir()}; verified = [load_semantic_pack(pack) for pack in packs.iterdir() if pack.name.endswith('.json')]; assert verified"

USER aegisguard

ENTRYPOINT ["python", "-m", "aegisguard_ulpf"]
CMD ["--help"]
