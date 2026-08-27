# Air-Gap Deployment

AegisGuard-ULPF processes supplied logs locally. It has no cloud API
integration or runtime internet client. The supplied Docker runtime installs
the already-built project from its local wheelhouse with `--no-index`.

For an offline environment, obtain the base image and build dependencies on a
connected build workstation first. After that preparation, use the following
transfer path without network access:

```text
Build image
  -> Export image
  -> Transfer offline
  -> Load image
  -> Run container
  -> Process logs
  -> Generate OCSF
  -> Verify integrity
```

Build the local image, export it with the existing bundle tooling, and verify
the copied archive before loading it on the offline host:

```powershell
docker build -f docker/Dockerfile -t aegisguard-ulpf:0.1.0 .
python scripts/build_airgap_bundle.py --image aegisguard-ulpf:0.1.0 --output .\airgap-bundle
# Transfer airgap-bundle by approved removable media.
python .\airgap-bundle\verify_airgap_bundle.py --bundle .\airgap-bundle
docker load --input .\airgap-bundle\aegisguard-ulpf-image.tar
```

The image package and its semantic-pack metadata are verified locally. Input
logs remain local, generated OCSF JSONL is local, and the raw-evidence
SHA-256/hash-chain check is also local.

Run the no-network demonstration from the source checkout:

```powershell
python demo/run_airgap_demo.py
```
