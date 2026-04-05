# ShadowLab YARA Validation

This document records the current local YARA pack layout and the latest validation checkpoint.

## Repositories In Use

ShadowLab currently builds the local YARA layer from:

- `C:\Users\ulfat\Documents\shadowlab-detection-lab\plugins\rules`
- `C:\Users\ulfat\Documents\rules-master`
- `C:\Users\ulfat\Documents\signature-base-master`

Known noisy rules removed from the enterprise pack:

- `RAT_PoetRATPython.yar`
- `domain.yar`

## Current Pack State

Latest verified health:

- `enterprise_rules_requested = 1163`
- `enterprise_rules_loaded = 1163`
- `compile_error_count = 0`

Current pack counts:

- `rules_master = 434`
- `signature_base = 726`
- `community = 1160`
- `enterprise = 1163`
- `balanced = 565`
- `fast = 2`
- `memory = 3`

## Detection Flow

1. calculate file context and hash
2. query `YARAify`
3. run local `enterprise` YARA if needed
4. combine local YARA, memory YARA, and threat-intel context into the fused verdict
5. expose the result through triage, response planning, telemetry, and desktop views

## Validation Inputs

Validated sample set:

- `C:\Users\ulfat\Documents\inceptor-main\inceptor\libs\public\x64\BYPASS-DINVOKE.dll`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\libs\public\x64\BYPASS-DINVOKE_MANUAL_MAPPING.dll`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\templates\public\amsi\bypass-classic.cs`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\templates\public\csharp\process_injection\classic-dinvoke_manual_mapping.cs`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\syscalls\syswhispers\example-output\syscalls.asm`

## Commands Used

```powershell
python -m unittest tests.test_api_load tests.test_threat_intelligence tests.test_security tests.test_triage_error_handling
```

```powershell
python -m py_compile plugins\yara_scanner.py api\main.py database.py plugins\memory_forensics.py desktop\main.py threat_intelligence.py
```

## Validation Corpus

ShadowLab includes a repeatable detection-validation corpus:

- [config/detection_validation_corpus.json](/C:/Users/ulfat/Documents/shadowlab-detection-lab/config/detection_validation_corpus.json)
- [scripts/validate_detection_corpus.py](/C:/Users/ulfat/Documents/shadowlab-detection-lab/scripts/validate_detection_corpus.py)

Run it with:

```powershell
python scripts\validate_detection_corpus.py
```

## Current Assessment

The current YARA state is a good fit for ShadowLab's Windows-focused detection and response workflow:

- local YARA is active
- `YARAify` remains the first external lookup
- `Inceptor_*` and `Memory_*` rules stay high signal
- noisy utility rules no longer dominate verdicts
- compile health is clean

updated

