(.venv) PS C:\Users\saran\AegisGuard-ULPF> python demo/run_final_demo.py
>> python demo/run_unknown_log_demo.py
>> python demo/run_semantic_pack_demo.py
>> python demo/run_parser_drift_demo.py
>> python demo/run_airgap_demo.py
>> python demo/run_traceability_demo.py
>> pytest

=== AegisGuard-ULPF Final SIH Demo ===

[1] Multi-source log processing
PASS

[2] Windows Security -> OCSF -> SIEM
PASS

[3] Multi-vendor normalization
PASS

[4] Evidence preservation
PASS

[5] Hash-chain verification
PASS

[6] Integrity verification
PASS

Final Status:
AegisGuard-ULPF pipeline operational

=== Tier-0 Unknown Log Handling ===

Raw preserved: PASS

Vendor:
unknown

Security meaning:
NOT INFERRED

Mapping status:
incomplete

Coverage:
0%

Unmapped fields:
available

Result:
LOG ACCEPTED WITHOUT LOSS

=== Semantic Pack Loading Demo ===

Pack loaded:
DemoVendor

Engine modification:
NONE

Parser engine:
UNCHANGED

Normalization:
SUCCESS

=== Parser Drift Detection ===

Baseline:
Fortigate Traffic

Coverage:
95%

After update:

Coverage:
65%

Alert:

PARSER_DRIFT DETECTED

=== Air Gap Deployment Demo ===

Internet dependency:
NONE

Cloud dependency:
NONE

Local processing:
PASS

OCSF generation:
PASS

Traceability verification:
PASS

=== AegisGuard-ULPF Hash Chain Traceability ===
OCSF raw_id: RAW-a4583b1eb56837448c848800c3855772e2ab05619f724b9690fc76bfccb669e6
Original event found: YES
SHA256 verified: PASS
Hash chain valid: PASS
Integrity: PASS
================================================= test session starts =================================================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\saran\AegisGuard-ULPF
configfile: pyproject.toml
plugins: anyio-4.14.2
collected 351 items                                                                                                    

tests\contract\test_common_event_json_schema.py .........                                                        [  2%]
tests\contract\test_common_event_model.py ..........................                                             [  9%]
tests\contract\test_detection_contract.py ...                                                                    [ 10%]
tests\contract\test_ocsf_infrastructure.py ...................                                                   [ 16%]
tests\contract\test_parser_contract.py ..                                                                        [ 16%]
tests\integration\test_aegisguard_demo.py .                                                                      [ 17%]
tests\integration\test_build5_end_to_end.py .....xx.x                                                            [ 19%]
tests\integration\test_demo_siem_flow.py .                                                                       [ 19%]
tests\integration\test_final_demo.py .                                                                           [ 20%]
tests\integration\test_processing_pipeline.py ....                                                               [ 21%]
tests\integration\test_siem_adapter.py ......                                                                    [ 23%]
tests\integration\test_siem_contract_mapper.py ....                                                              [ 24%]
tests\integration\test_unified_visibility.py .                                                                   [ 24%]
tests\unit\detection\test_detection_engine.py .......                                                            [ 26%]
tests\unit\detection\test_event_family_detector.py ...........                                                   [ 29%]
tests\unit\detection\test_format_detector.py ..........                                                          [ 32%]
tests\unit\detection\test_source_detector.py ........                                                            [ 34%]
tests\unit\fallback\test_tier0.py .........                                                                      [ 37%]
tests\unit\ingestion\test_windows_adapter.py ......                                                              [ 39%]
tests\unit\normalization\ocsf\test_windows_security_mapper.py ........                                           [ 41%]
tests\unit\normalization\test_common_event_mapper.py ......................................................      [ 56%]
tests\unit\normalization\test_mapping_fidelity.py ........                                                       [ 58%]
tests\unit\normalization\test_normalization_engine.py ............                                               [ 62%]
tests\unit\normalization\test_normalization_validators.py ........................                               [ 69%]
tests\unit\outputs\test_jsonl_output.py .......                                                                  [ 71%]
tests\unit\packaging\test_offline_bundle.py ..                                                                   [ 71%]
tests\unit\packaging\test_phase5_deployment.py ..                                                                [ 72%]
tests\unit\packaging\test_release_and_airgap.py .........                                                        [ 74%]
tests\unit\parsing\test_demo_vendor_normalization.py ..                                                          [ 75%]
tests\unit\parsing\test_linux_syslog.py ....                                                                     [ 76%]
tests\unit\parsing\test_registry.py .....                                                                        [ 78%]
tests\unit\privacy\test_privacy_engine.py ..............                                                         [ 82%]
tests\unit\semantic_packs\test_demo_vendor_pack.py ...                                                           [ 82%]
tests\unit\semantic_packs\test_ocsf_bindings.py .....                                                            [ 84%]
tests\unit\semantic_packs\test_panos_traffic_pack.py .............................                               [ 92%]
tests\unit\semantic_packs\test_semantic_pack_signing.py ......                                                   [ 94%]
tests\unit\test_exporters_and_ml.py ..                                                                           [ 94%]
tests\unit\test_fidelity_measurement.py ....                                                                     [ 96%]
tests\unit\test_parser_drift.py ...                                                                              [ 96%]
tests\unit\test_unknown_log_handling.py ....                                                                     [ 98%]
tests\unit\traceability\test_traceability.py ....                                                                [ 99%]
tests\unit\traceability\test_traceability_views.py .                                                             [ 99%]
tests\unit\traceability\test_verify_cli.py ..                                                                    [100%]

=========================================== 348 passed, 3 xfailed in 4.95s ============================================
(.venv) PS C:\Users\saran\AegisGuard-ULPF>