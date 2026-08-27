# Windows Security Event to OCSF mapping

This mapping is pinned to OCSF **1.9.0** (`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`), the repository-wide pin in `src/aegisguard_ulpf/normalization/ocsf/version.py`.

The mapping boundary is:

```text
Windows Security Event -> Windows adapter -> ULPF CommonEvent -> OCSF event
```

No AegisGuard SIEM code is read or changed by this mapping.

## Supported events

| Windows Event ID | Meaning | OCSF class | `class_uid` | `activity_id` | `type_uid` | `status_id` | `severity_id` |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 4624 | Successful logon | Authentication | 3002 | 1 (`Logon`) | 300201 | 1 (`Success`) | 1 (`Informational`) |
| 4625 | Failed logon | Authentication | 3002 | 1 (`Logon`) | 300201 | 2 (`Failure`) | 2 (`Low`) |
| 4688 | Process creation | Process Activity | 1007 | 1 (`Launch`) | 100701 | 1 (`Success`) | 1 (`Informational`) |

Authentication events use category UID `3` (Identity & Access Management); Process Activity uses category UID `1` (System Activity). `type_uid` is always calculated as `class_uid * 100 + activity_id`.

## Field mapping

| Windows field | ULPF CommonEvent | OCSF field |
| --- | --- | --- |
| `EventID` | `vendor.vendor_event_id`, `classification` | class, activity, status, severity, and `type_uid` selected by this table |
| `TimeCreated`, `TimeCreatedUtc`, or `SystemTime` | `timestamps.event_time` | `time` (Unix milliseconds) |
| `TargetUserName`, `User`, or `SubjectUserName` | `actor.user` | `user.name` (Authentication) or `actor.user.name` (Process Activity) |
| `IpAddress`, `SourceIP`, or `IP` | `src_endpoint.ip` | `src_endpoint.ip` and an IP `observables` entry (`type_id: 2`) |
| `Computer` or `WorkstationName` | `device.hostname` | `device.hostname` |
| `LogonType` | `details.logon_type` | `logon_type` |
| `NewProcessName` or `ProcessName` | `resource.name` | `process.name` |
| `NewProcessId` | — | `process.pid`, when it is an integer |
| `CommandLine` | `details.command_line` | `process.cmd_line` |

Every output includes `metadata.version`, `metadata.product.vendor_name`, and `metadata.product.name` as required by the pinned ULPF OCSF contract.

## Preservation and validation

The Windows adapter preserves the full input as canonical JSON in `raw_data`. Every top-level source field not mapped above is copied unchanged to `unmapped.windows_security`; the intermediary `CommonEvent.vendor_fields` also holds a complete copy of the original object. Thus fields are never silently dropped.

`OCSFValidator` validates the pinned envelope, class/category/activity consistency, metadata version, and the structure of `observables` and `unmapped`. Source-specific tests cover all three event IDs, raw preservation, unmapped-field retention, and invalid observable rejection.

## Entry points and samples

- `map_windows_security_event_to_common_event()` produces the ULPF internal representation.
- `map_windows_security_event_to_ocsf()` produces the validated OCSF event.
- `examples/windows_ocsf_4624.json`, `examples/windows_ocsf_4625.json`, and `examples/windows_ocsf_4688.json` are representative outputs.
