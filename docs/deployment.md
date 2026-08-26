# Air-Gap Deployment

## Connected preparation

Build the image and verify the bundled Semantic Packs on a connected build
machine:

```sh
docker build -f docker/Dockerfile -t aegisguard-ulpf:0.1.0 .
python scripts/verify_release_packs.py
python scripts/build_airgap_bundle.py --image aegisguard-ulpf:0.1.0 --output dist/airgap
```

The image build installs only from its builder-produced wheelhouse in the
runtime stage. Release verification uses bundled Ed25519 public keys; private
signing keys are not included.

## Transfer

Transfer the complete `dist/airgap` directory through the organization's
approved physical/offline process. The bundle contains an exported Docker image,
Semantic Pack verification metadata, and transfer checksums.

## Air-gapped deployment

On the offline machine, verify the transfer, load the image, then run it with
network access disabled:

```sh
python dist/airgap/verify_airgap_bundle.py --bundle dist/airgap
docker load -i dist/airgap/aegisguard-ulpf-image.tar
docker run --rm --network none aegisguard-ulpf:0.1.0 --help
```

No cloud service or PyPI access is required after image export. Ed25519
signatures authenticate Semantic Packs, while the bundle checksum verifies the
transport artifact. Mount raw evidence and Build #9 output directories
separately when needed; the `RawEvidenceStore` remains authoritative:

```sh
docker run --rm --network none -v <evidence-dir>:/evidence:ro \
  aegisguard-ulpf:0.1.0 verify <event-id> --store /evidence
```
