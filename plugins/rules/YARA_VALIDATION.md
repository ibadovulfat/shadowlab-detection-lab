# ShadowLab YARA Validation

This document records the current local YARA pipeline, the repositories in use, the rule-pack composition, and the latest validation results against `Inceptor`.

## Repositories In Use

ShadowLab currently builds the local YARA layer from:

- `C:\Users\ulfat\Documents\shadowlab-detection-lab\plugins\rules`
- `C:\Users\ulfat\Documents\rules-master`
- `C:\Users\ulfat\Documents\signature-base-master`

Community utility rules that created low-value noise or runtime warnings were removed from the enterprise pack, including:

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

The current process and file flow is:

1. calculate file context and hash
2. query `YARAify`
3. if needed, run local `enterprise` YARA
4. combine local YARA, YARAify, threat-intel, and memory findings into a fused verdict
5. expose the result through triage, response planning, telemetry, and desktop views

Memory artifacts use the dedicated `memory` pack.

## Test Inputs

Validated sample set:

- `C:\Users\ulfat\Documents\inceptor-main\inceptor\libs\public\x64\BYPASS-DINVOKE.dll`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\libs\public\x64\BYPASS-DINVOKE_MANUAL_MAPPING.dll`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\templates\public\amsi\bypass-classic.cs`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\templates\public\csharp\process_injection\classic-dinvoke_manual_mapping.cs`
- `C:\Users\ulfat\Documents\inceptor-main\inceptor\syscalls\syswhispers\example-output\syscalls.asm`

## Observed Detection Results

### `BYPASS-DINVOKE.dll`

- `match_count = 21`
- `active_match_count = 21`
- `severity = critical`
- `confidence = high`

Strongest rules:

- `Inceptor_AMSI_WLDP_ETW_Bypass`
- `Inceptor_DInvoke_ManualMap_Tradecraft`
- `Inceptor_Process_Injection_Syscall_Chain`
- `Inceptor_Unhook_NTDLL_Tradecraft`
- `Inceptor_SysWhispers_Direct_Syscalls`
- `Inceptor_DInvoke_PE_Manual_Map_Extended`
- `Inceptor_AMSI_Session_Patch_Extended`
- `Inceptor_APC_Remote_Thread_Tradecraft`

### `BYPASS-DINVOKE_MANUAL_MAPPING.dll`

- `match_count = 20`
- `active_match_count = 20`
- `severity = critical`
- `confidence = high`

Strongest rules:

- `Inceptor_AMSI_WLDP_ETW_Bypass`
- `Inceptor_DInvoke_ManualMap_Tradecraft`
- `Inceptor_Process_Injection_Syscall_Chain`
- `Inceptor_Unhook_NTDLL_Tradecraft`
- `Inceptor_SysWhispers_Direct_Syscalls`
- `Inceptor_DInvoke_PE_Manual_Map_Extended`
- `Inceptor_APC_Remote_Thread_Tradecraft`
- `Memory_AMSI_ETW_Patch_Sequence`

### `bypass-classic.cs`

- `match_count = 4`
- `active_match_count = 4`
- `severity = critical`
- `confidence = high`

Detected with:

- `Inceptor_AMSI_WLDP_ETW_Bypass`
- `Inceptor_AMSI_Session_Patch_Extended`
- `Memory_AMSI_ETW_Patch_Sequence`
- `contains_base64`

### `classic-dinvoke_manual_mapping.cs`

- `match_count = 4`
- `active_match_count = 4`
- `severity = critical`
- `confidence = high`

Detected with:

- `Inceptor_DInvoke_ManualMap_Tradecraft`
- `Inceptor_Process_Injection_Syscall_Chain`
- `Inceptor_SysWhispers_Direct_Syscalls`
- `contains_base64`

### `syscalls.asm`

- `match_count = 7`
- `active_match_count = 7`
- `severity = critical`
- `confidence = high`

Detected with:

- `Inceptor_Process_Injection_Syscall_Chain`
- `Inceptor_SysWhispers_Direct_Syscalls`
- `DebuggerCheck__QueryInfo`
- `DebuggerHiding__Thread`
- `DebuggerHiding__Active`
- `disable_dep`
- `contains_base64`

## Commands Used

Validation commands used during this checkpoint:

```powershell
python -m unittest tests.test_api_load tests.test_threat_intelligence tests.test_security tests.test_triage_error_handling
```

```powershell
python -m py_compile plugins\yara_scanner.py api\main.py database.py plugins\memory_forensics.py desktop\main.py threat_intelligence.py
```

## Validation Corpus

ShadowLab now includes a repeatable validation corpus manifest for detection regression checks:

- [config/detection_validation_corpus.json](/C:/Users/ulfat/Documents/shadowlab-detection-lab/config/detection_validation_corpus.json)
- [scripts/validate_detection_corpus.py](/C:/Users/ulfat/Documents/shadowlab-detection-lab/scripts/validate_detection_corpus.py)

The validator checks:

1. whether the sample still triggers at least one expected high-signal YARA rule
2. whether the sample still reaches the expected minimum structural static-analysis score
3. whether any sample went missing from the analyst corpus

Run it with:

```powershell
python scripts\validate_detection_corpus.py
```

## Current Assessment

The current YARA state is suitable for ShadowLab's Windows-focused detection-and-response workflow:

- local YARA is active
- `YARAify` remains the first external lookup
- high-signal `Inceptor_*` and `Memory_*` rules are prioritized
- broad noisy utility rules removed from the enterprise pack no longer pollute verdicts
- compile health is clean
