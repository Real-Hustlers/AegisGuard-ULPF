# Tier-0 Unknown Log Handling

Tier-0 is the safe fallback for an input that has no supported semantic
parser. The input is accepted and its raw content remains attached to the
fallback event; it is never silently discarded because its vendor is unknown.

Dropping unknown data creates a forensic blind spot. An analyst cannot later
onboard the source, validate a detection, or prove what was received if the
original evidence is absent. Tier-0 preserves the raw event and safely
extracts only structural content (JSON, XML, CSV, or text) into
`vendor_fields`.

Tier-0 does not guess security meaning. Strings such as `deny`, `critical`,
or `malware` can be product-specific and assigning a category, action,
severity, or outcome from them would manufacture evidence. Its normalized
fields remain unset, `mapping_status` is `incomplete`, and fidelity coverage
is therefore `0%`.

The result is an accepted, evidence-preserving ULPF event with all unresolved
fields available for later, reviewed parser or semantic-pack onboarding.

Run the presentation demo locally:

```powershell
python demo/run_unknown_log_demo.py
```
