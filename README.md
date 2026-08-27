# AegisGuard-ULPF

> **Different logs. One security language. Every transformation accounted for.**

**AegisGuard-ULPF** is an auditable, air-gap-capable log preprocessing framework for **SIH26156 — Universal Log Pre-processing Framework (ULPF)**.

It is **not a SIEM**. It sits **before** SIEMs, Data Lakes, analytics platforms, and other security tooling.

Its goal is to convert heterogeneous perimeter-security logs into a consistent semantic representation and OCSF-oriented output while preserving the original event, measuring normalization fidelity, and maintaining verifiable traceability.

---

## 1. Problem Statement — SIH26156

Modern enterprise environments generate logs from many different sources, including:

- Network devices
- Servers
- Operating systems
- Applications
- Databases
- Cloud services
- Containers
- Endpoint security tools
- Identity and Access Management systems
- IoT devices
- Other hardware and software platforms

These logs may arrive in formats such as:

- Syslog
- JSON
- XML
- CSV
- CEF
- LEEF
- Proprietary vendor formats
- Application-specific schemas

Security teams currently depend heavily on source-specific parsers and normalization rules. This makes centralized monitoring, incident investigation, threat analytics, compliance workflows, and downstream analytics harder to maintain across heterogeneous environments.

### Current SIH Scope

The current SIH scope focuses on preprocessing **perimeter-network/security-device-generated logs and events** regardless of vendor, source, format, or technology.

AegisGuard-ULPF is designed as a broader extensible framework, while the current implementation and demo focus on selected perimeter-security sources.

---

## 2. Project Positioning

AegisGuard-ULPF is a **preprocessing layer**, not a replacement for SIEM or analytics products.

```text
Security Devices / Log Sources
            |
            v
     AegisGuard-ULPF
            |
            +--------> SIEM
            +--------> Data Lake
            +--------> Security Analytics
            +--------> Threat Hunting
            +--------> AI / ML Pipelines
```

### Core One-Liner

> AegisGuard-ULPF is an auditable, air-gap-capable log preprocessing framework that uses versioned vendor Semantic Packs to convert heterogeneous perimeter-security logs into OCSF-oriented events while measuring normalization fidelity and maintaining verifiable traceability to the original event.

---

## 3. Main Product Thesis — Auditable Normalization

The main differentiation of AegisGuard-ULPF is **auditable normalization**.

The framework is designed to answer:

- What fields were extracted?
- What fields were semantically mapped?
- What remained unmapped?
- What was dropped?
- Was the original raw event preserved?
- Can the normalized/OCSF event be traced back to the original event?
- Can the integrity of the preserved raw event be verified?

The engineering principle is:

> **Wrong-but-valid output is worse than explicitly incomplete output.**

AegisGuard-ULPF should prefer an explicit incomplete mapping over invented security semantics.

---

## 4. Current Implementation Baseline

The existing project baseline already contains implementation for:

- Format detection
- Vendor/product detection
- Event-family detection
- Parser registry
- FortiGate parsers
- Cisco ASA/IOS parsers
- Palo Alto PAN-OS parsers
- Traffic/VPN/router/system event handling
- Common normalization
- Initial OCSF mapping
- Batch processing
- Streaming/Syslog ingestion
- Storage
- CLI

### Historical Test Baseline

A previous verified project baseline reported:

```text
77 passing tests
```

> **Important:** the current pre-refactor baseline must be re-recorded on the active integration branch before using this number as a final SIH claim.

Primary regression command:

```powershell
python -m pytest
```

---

## 5. Currently Supported Vendor Families

Current parser work is centered on:

| Vendor / Product | Event Families |
|---|---|
| Fortinet / FortiGate | Traffic, VPN, System |
| Cisco ASA / IOS | Traffic, Router/System-related events |
| Palo Alto / PAN-OS | Traffic and supported security/system event families |

Exact supported event families should be updated from the latest verified integration state before final release/demo.

---

## 6. Target Processing Architecture

```text
                    KNOWLEDGE PLANE
             (outside secure runtime)

 Official Vendor Documentation
              +
       Validation Corpus
              |
              v
      Semantic Pack Builder
              |
      Validation / Review
              |
              v
 Signed + Versioned Semantic Pack


                    RUNTIME PLANE
              (air-gap capable)

 Raw Log / Event
       |
       v
 Format / Source Detection
       |
       v
 Semantic Pack Lookup
       |
       v
 Parsing / Structural Extraction
       |
       v
 ULPF Common Event Schema
       |
       +------------------------+
       |                        |
       v                        v
 Mapping Fidelity          Raw Evidence Path
       |                        |
       v                        v
 Sensitivity             Integrity / Hash Chain
 Classification                |
       |                        v
       v                 Restricted Evidence Store
 Output Policy                  |
       |                        v
       v                    Traceability
 OCSF Mapping
       |
       v
 SIEM / Data Lake / Analytics
```

---

## 7. ULPF Common Event Schema v1

**Owner:** Yogendiran / Joshua  
**Build Order:** #1  
**Status:** IN DEVELOPMENT

The previous schema is relatively flat:

```text
src_ip
dst_ip
src_port
dst_port
protocol
action
```

The target schema is being refactored toward a stable nested semantic model such as:

```yaml
src_endpoint:
  ip:
  port:
  hostname:
  interface:
  zone:

dst_endpoint:
  ip:
  port:
  hostname:
  interface:
  zone:

network:
  protocol:
  bytes_in:
  bytes_out:
  packets_in:
  packets_out:

device:
actor:
policy:
nat:

timestamps:
  event_time:
  observed_time:
  processed_time:

traceability:
  u_id:
  raw_id:

unmapped:
```

### Design Rules

- ULPF must **not blindly copy OCSF**.
- ULPF is the stable intermediate semantic model.
- It must map cleanly into OCSF.
- Vendor-specific/unmapped information must be preserved.
- Required, optional, absent, and unmapped fields must remain distinguishable.
- Existing FortiGate, Cisco, and Palo Alto event families must remain supported.

---

## 8. Semantic Packs

**Runtime Owner:** Yogendiran / Joshua  
**Semantics / OCSF Binding Owner:** Nisithaa  
**Status:** PLANNED / DEPENDENT ON SCHEMA V1

AegisGuard-ULPF separates:

```text
Stable Runtime
      +
Vendor / Product / Version / Event Knowledge
```

A Semantic Pack is intended to be one signed/versioned artifact containing concepts such as:

```text
manifest
syntax
semantics
OCSF binding
tests
provenance
optional sensitivity metadata
```

### Safety Constraint

Semantic Packs must not contain arbitrary executable behavior such as:

- Python execution
- `eval`
- shell execution
- Jinja execution
- arbitrary plugin execution

The runtime will interpret a restricted declarative language controlled by AegisGuard-ULPF.

### First Proof Target

Only **one existing parser/event family** should initially be converted to a Semantic Pack.

The project will compare:

```text
Existing Python Parser Output
            vs
Semantic Pack Runtime Output
```

The semantic ULPF output should be equivalent before broader migration is attempted.

---

## 9. Graceful Unsupported-Source Handling — Tier 0

**Owner:** Yogendiran / Joshua  
**Build Order:** #5  
**Status:** PLANNED

When no matching Semantic Pack is available:

```text
No Matching Pack
      |
      v
Raw Event Preserved
      |
      v
Safe Structural Extraction
      |
      v
Unresolved Fields -> unmapped
      |
      v
mapping_status = incomplete
      |
      v
No Guessed Security Semantics
```

The project avoids presenting unsupported inputs as correctly understood when semantic confidence is not justified.

---

## 10. OCSF Mapping

**Owner:** Nisithaa  
**Build Order:** #2  
**Status:** IN DEVELOPMENT

The existing OCSF mapping is considered **initial** and must not be assumed correct.

The target pipeline is:

```text
ULPF Common Event
        |
        v
Pinned OCSF Version
        |
        v
Validated OCSF Event
```

Representative mapping work includes:

- Network Activity
- Authentication
- Tunnel Activity for VPN where appropriate
- Detection Finding
- Appropriate system/config event classes
- `activity_id`
- `type_uid`
- `observables[]`
- `unmapped`
- metadata
- vendor/product/source metadata

### Important VPN Rule

VPN events must be mapped according to semantics.

For example:

```text
Credential authentication -> Authentication semantics
Tunnel/session establishment -> Tunnel semantics
Tunnel teardown -> Tunnel semantics
```

VPN must not automatically be treated as authentication only.

### Compliance Claim Rule

Do not claim **official OCSF compliance** until:

- One OCSF version is explicitly pinned
- Required structure is verified
- Representative events are validated
- Tests validate the pinned contract
- Winston independently verifies the implementation

Until then, use wording such as:

> **OCSF-oriented mapping**

---

## 11. Forensic Integrity and Traceability

**Owner:** Saran  
**Build Order:** #3  
**Status:** IN DEVELOPMENT

The project is designed so every processed event can remain traceable to its original raw event.

### Separate Concepts

The implementation must not confuse:

- Event identity
- Raw SHA-256 hash
- Hash-chain value

These are separate concepts.

### Planned Integrity Flow

```text
Raw Event
   |
   +--> Deterministic / Replay-Safe Event Identity
   |
   +--> SHA-256 of Original Raw Bytes
   |
   +--> Sequential Tamper-Evident Hash Chain
```

Example concept:

```text
event1 -> H1
H1 + event2 -> H2
H2 + event3 -> H3
```

This is a **hash chain**, not a Merkle tree.

### Traceability Goal

```text
OCSF Event
    |
    v
ULPF Normalized Event
    |
    v
Original Raw Event
    |
    v
Integrity Verification
```

Planned CLI target:

```powershell
ulpf verify <event-id>
```

Possible verified result:

```text
Original event found
Raw SHA-256 verified
Hash chain verified
Integrity: PASS
```

This output must not be used in a final demo until implemented and independently verified.

### Accurate Terminology

Use:

- tamper-evident
- integrity-verifiable
- designed to support forensic traceability

Do not claim:

- tamper-proof
- court admissible
- non-repudiation
- GDPR compliant
- DPDP compliant

unless separately and rigorously proven.

---

## 12. Mapping Fidelity

**Owner:** Saran  
**Build Order:** #6  
**Status:** PLANNED

AegisGuard-ULPF should not present one misleading global “accuracy %”.

Instead, it should track separately:

```text
fields extracted
fields semantically mapped
fields unmapped
fields dropped

extraction coverage
semantic coverage

raw_preserved
integrity_verified
```

Important distinctions:

```text
unmapped != mapped
absent   != unmapped
dropped  = explicitly recorded
```

This forms the measurable side of **Auditable Normalization**.

---

## 13. Sensitivity Classification and Privacy-Aware Outputs

**Owner:** Nisithaa  
**Build Order:** #8  
**Status:** PLANNED

Semantic knowledge may classify what a field represents.

Initial sensitivity classes may include:

```text
normal
network_identifier
personal_identifier
credential
secret
potentially_sensitive
```

Example concepts:

```yaml
user:
  semantic_role: actor.user.name
  sensitivity: personal_identifier

srcip:
  semantic_role: src_endpoint.ip
  sensitivity: network_identifier

password:
  sensitivity: credential
```

### Separation of Responsibility

```text
Semantic Pack
    -> Classifies WHAT the field is

Customer / Sink Policy
    -> Decides WHAT TO DO with it
```

Initial SIH scope:

### Sink Profiles

- SOC
- Data Lake

### Actions

- retain
- mask
- pseudonymize
- drop

The goal is a small, understandable privacy layer — not a complex compliance or policy DSL.

---

## 14. Clean Output Architecture

**Owner:** Saran  
**Build Order:** #9  
**Status:** PLANNED

Target outputs:

```text
raw_events.jsonl
normalized_events.jsonl
ocsf_events.jsonl
```

Optional:

```text
ocsf_events.parquet
```

Purpose:

| Output | Meaning |
|---|---|
| `raw_events.jsonl` | Raw/evidence representation |
| `normalized_events.jsonl` | Pure ULPF Common Schema |
| `ocsf_events.jsonl` | Independently usable OCSF event |
| `ocsf_events.parquet` | Optional Data Lake output |

Traceability identifiers should connect all representations.

The final OCSF output should **not** contain the entire ULPF event wrapped inside an `ocsf` property.

---

## 15. Air-Gap Deployment

**Owner:** Saran  
**Build Order:** #10  
**Status:** PLANNED

The target runtime must not require mandatory access to:

- Internet
- Online AI
- Cloud APIs
- Remote OCSF schemas
- CDN-hosted resources

Planned packaging includes:

- Dockerfile
- `compose.yaml`
- Offline bundle
- Semantic Pack verification/signing
- Checksums
- SBOM where practical

Target online-free startup:

```powershell
docker compose up
```

Target offline transfer model:

```text
docker save
    |
Approved Transfer
    |
docker load
    |
Run
```

Do not describe air-gap deployment as demonstrated until Winston independently verifies the packaged runtime with network access disabled.

---

## 16. Independent Validation

**Owner:** Winston

Winston's role is independent feature validation, not primary feature development.

A feature should not become a final README/PPT/video claim simply because developer tests pass.

### Validation Gates

| Gate | Area |
|---|---|
| Gate 0 | Baseline |
| Gate 1 | ULPF Schema |
| Gate 2 | OCSF |
| Gate 3 | Traceability |
| Gate 4 | Semantic Pack Runtime |
| Gate 5 | Tier 0 Fallback |
| Gate 6 | Mapping Fidelity |
| Gate 7 | Privacy |
| Gate 8 | Output Purity |
| Gate 9 | Air-Gap |
| Gate 10 | Benchmark |

Winston should test adversarial cases such as:

- malformed input
- missing fields
- duplicates
- replayed events
- altered raw events
- modified hash chain
- invalid event ID
- malformed Semantic Packs
- unsupported sources
- incorrect mappings
- output contamination
- runtime behavior with network disabled

Failures should be classified as:

```text
IMPLEMENTATION BUG
TEST BUG
CONTRACT AMBIGUITY
INTEGRATION BUG
EXPECTED LIMITATION
```

---

## 17. Feature Status

A feature should be called **IMPLEMENTED / DEMO READY** only when:

1. The technical owner says the code is complete
2. Winston independently verifies it
3. It exists in the latest merged integration state
4. The demo can reproduce it

Current working status from the latest shared project plan:

| Feature | Owner | Current Status | Final Demo Claim? |
|---|---|---|---|
| Format detection | Existing baseline | BASELINE | Re-verify before final claim |
| Vendor/product detection | Existing baseline | BASELINE | Re-verify before final claim |
| Event-family detection | Existing baseline | BASELINE | Re-verify before final claim |
| Parser registry | Existing baseline | BASELINE | Re-verify before final claim |
| FortiGate parsers | Existing baseline | BASELINE | Re-verify before final claim |
| Cisco ASA/IOS parsers | Existing baseline | BASELINE | Re-verify before final claim |
| Palo Alto PAN-OS parsers | Existing baseline | BASELINE | Re-verify before final claim |
| Batch processing | Existing baseline | BASELINE | Re-verify before final claim |
| Streaming/Syslog ingestion | Existing baseline | BASELINE | Re-verify before final claim |
| Storage | Existing baseline | BASELINE | Re-verify before final claim |
| CLI | Existing baseline | BASELINE | Re-verify before final claim |
| Common Schema v1 | Joshua | IN DEVELOPMENT | No |
| Pinned OCSF Mapping v1 | Nisithaa | IN DEVELOPMENT | No |
| Forensic Integrity + Traceability | Saran | IN DEVELOPMENT | No |
| Semantic Pack Runtime | Joshua | PLANNED | No |
| Tier 0 Fallback | Joshua | PLANNED | No |
| Mapping Fidelity | Saran | PLANNED | No |
| Semantic Pack Bindings | Nisithaa | PLANNED | No |
| Sensitivity / Privacy v1 | Nisithaa | PLANNED | No |
| Clean Output Architecture | Saran | PLANNED | No |
| Air-Gap Packaging | Saran | PLANNED | No |
| Benchmark | Winston | PLANNED AFTER INTEGRATION | No |

This table should be updated continuously as feature branches are tested and merged.

---

## 18. Build Order

```text
#1  Common Event Schema v1
         |
         +--> #2 Pinned OCSF Mapping v1
         |
         +--> #3 Forensic Integrity + Traceability
         |
         v
#4  Semantic Pack Runtime v1
         |
         v
#5  Tier 0 Graceful Fallback
         |
         v
#6  Mapping Fidelity
         |
         v
#7  Semantic Pack Semantics + OCSF Bindings
         |
         v
#8  Sensitivity Classification + Minimal Privacy
         |
         v
#9  Clean Output Architecture
         |
         v
#10 Pack Signing + Docker / Air-Gap Packaging
         |
         v
     Independent Benchmark
```

---

## 19. Installation

> **Status:** repository-specific installation commands must be verified from the active branch before final publication.

Recommended final README content should include:

```powershell
# Clone repository
# Create/activate environment
# Install dependencies
# Run tests
python -m pytest

# Run CLI
# <verified command to be inserted>

# Run streaming/syslog ingestion
# <verified command to be inserted>

# Run Docker deployment
# docker compose up
# Only after air-gap packaging is implemented and verified
```

Do not publish guessed setup commands.

---

## 20. Demo Flow

Once all required features are verified, the preferred SIH demo is:

```text
FortiGate + Cisco + Palo Alto Raw Logs
                |
                v
              Ingest
                |
                v
       Unified Normalization
                |
                v
               OCSF
                |
                v
       Fidelity Information
                |
                v
         Select One Event
                |
                v
      Trace Back to Raw Event
                |
                v
       Verify Raw Integrity
                |
                v
       Offline Deployment Proof
```

Only features marked **DEMO READY** should appear as working functionality in the final video.

---

## 21. Benchmarking

Benchmarking will be performed only after the integrated runtime is stable.

Planned test sizes:

```text
1,000 events
10,000 events
100,000 events
```

Record:

- Hardware
- Operating system
- Python/runtime version
- Worker/process configuration
- Total duration
- Events per second
- Average latency where meaningful
- Success count
- Failure count

Do not invent or extrapolate performance numbers.

---

## 22. Future Scope

The following are **future concepts**, not current implementation claims:

- Drain3-assisted pattern discovery
- AI-assisted Semantic Pack proposal generation
- Semantic Pack marketplace
- Advanced automatic onboarding
- Complex policy engine
- Kafka integration
- Kubernetes deployment
- Large-scale distributed processing

---

## 23. SIH26156 Requirement Mapping

| SIH Requirement | AegisGuard-ULPF Approach |
|---|---|
| Preserve complete raw event data | Separate raw/evidence path |
| Extract source-specific attributes | Vendor/event-family parsing |
| Normalize into common taxonomy | ULPF Common Event Schema |
| Maintain traceability | Raw ↔ ULPF ↔ OCSF identifiers + integrity work |
| Plug-and-play onboarding | Semantic Pack architecture |
| Unified visibility | Common normalized output |
| SIEM/Data Lake integration | OCSF-oriented and planned Parquet outputs |
| AI/ML-ready analytics | Structured standardized outputs |
| Reduce parser development effort | Reusable runtime + vendor knowledge separation |
| Air-gapped deployment | Offline runtime/package target |
| Platform independence | Docker packaging target |

Status of each row must follow the living implementation-status table above.

---

## 24. Team Responsibilities

| Team Member | Primary Responsibility |
|---|---|
| Yogendiran / Joshua | Common Schema, Semantic Pack Runtime, Tier 0 |
| Nisithaa | OCSF, Pack Semantics/Bindings, Sensitivity/Privacy |
| Saran | Traceability, Fidelity, Outputs, Air-Gap Packaging |
| Winston | Independent Validation and Benchmarking |
| Narendran | README, Documentation, Architecture, PPT, Story, Video, Q&A |
| Sudarsan | Supporting team member; no core critical-path ownership currently assigned |

---

## 25. Terminology and Claim Discipline

### Prefer

- currently supported
- designed to support
- OCSF-oriented
- explicitly incomplete
- tamper-evident
- integrity-verifiable
- air-gap-capable / designed for air-gapped deployment
- normalization fidelity
- auditable normalization

### Avoid Unless Proven

- fully universal
- 100% accurate
- zero data loss
- automatically understands every format
- official OCSF compliant
- tamper-proof
- court admissible
- GDPR compliant
- DPDP compliant

---

## 26. Project Principle

AegisGuard-ULPF is not intended to hide uncertainty.

It is intended to make uncertainty **visible, measurable, and traceable**.

> **Different logs. One security language. Every transformation accounted for.**

---

## License

**TODO:** Add the project's verified license information.

---

## Repository / SIH Links

- **Source Code:** TODO
- **SIH Problem Statement:** SIH26156 — Universal Log Pre-processing Framework
- **Architecture Document:** TODO
- **Demo Video:** TODO
- **Technical Presentation:** TODO
