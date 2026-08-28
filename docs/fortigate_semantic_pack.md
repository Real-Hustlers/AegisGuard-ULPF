# FortiGate Traffic Semantic Pack

## Scope

This onboarding covers one workflow only:

`Fortinet` → `FortiGate` → `traffic`

FortiGate VPN, router, and system events continue through their existing parser
paths. The parser registry, CommonEvent schema, NormalizationEngine, and OCSF
mapper are unchanged.

## Before

FortiGate Traffic vendor fields and Common Taxonomy mappings were implemented
in the existing Python parser. Source and event-family detection selected
`fortinet.fortigate.traffic` from the parser registry.

## After

The execution order for a detected FortiGate Traffic event is:

```text
Raw Log
  ↓
Source and Event-Family Detection
  ↓
Semantic Pack Resolver
  ↓
Restricted Generic Key-Value Extraction
  ↓
Declarative Common Taxonomy Mapping
  ↓
Existing NormalizationEngine
  ↓
Existing OCSF Mapper + Validated Binding
```

The signed, data-only pack is stored at
`examples/semantic_packs/fortigate_traffic/semantic_pack.json`. It declares:

- vendor, product, event family, and supported key-value format;
- vendor-field to legacy Common Taxonomy mappings;
- action, outcome, protocol, timestamp, and severity mappings;
- a validated OCSF 1.9.0 Network Activity binding;
- provenance and sensitivity metadata;
- preservation of every extracted vendor field.

The pack contains no Python, imports, templates, expressions, or executable
hooks. The runtime permits only its fixed declarative operation allowlist.
The pack must validate against the typed schema and its Ed25519 signature must
match the runtime-controlled `fortigate-traffic-v1` public trust anchor.

## Resolver and fallback behavior

`ProcessingPipeline` asks `SemanticPackResolver` for a pack only after normal
source and family detection. A match requires all three values:

```text
vendor = Fortinet
product = FortiGate
event_family = traffic
```

If the pack is absent, malformed, unsigned, untrusted, or cannot parse the
specific event, the resolver returns no result. The pipeline then performs the
same parser-registry lookup and parser call used before this onboarding. The
existing FortiGate Traffic parser remains available and unchanged.

## Compatibility

The semantic path retains the identifiers owned by `RawEvent`, preserves all
key-value fields in `vendor_fields`, and emits the same core traffic values as
the existing parser: timestamp, vendor/product, category/type/subtype,
action/outcome/severity, endpoints, protocol, and vendor event ID.

No changes were made to:

- the FortiGate parser;
- the parser registry;
- the CommonEvent schema;
- the NormalizationEngine;
- the OCSF mapper.

## Run the demonstration

```bash
python demo/run_fortigate_semantic_pack_demo.py
```

Successful output reports `LOADED`, Common Taxonomy `SUCCESS`, and OCSF
`SUCCESS`.
