rule Inceptor_AMSI_WLDP_ETW_Bypass
{
    meta:
        description = "Detects Inceptor-style AMSI, WLDP, and ETW bypass tradecraft markers"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "high"
    strings:
        $a1 = "AmsiScanBuffer" ascii wide
        $a2 = "WldpQueryDynamicCodeTrust" ascii wide
        $a3 = "EtwEventWrite" ascii wide
        $a4 = "VirtualProtect" ascii wide
        $a5 = "RtlMoveMemory" ascii wide
    condition:
        4 of them
}

rule Inceptor_DInvoke_ManualMap_Tradecraft
{
    meta:
        description = "Detects Inceptor DInvoke manual mapping and reflective invocation patterns"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "high"
    strings:
        $d1 = "DInvoke.DynamicInvoke" ascii wide
        $d2 = "GetLibraryAddress" ascii wide
        $d3 = "CallMappedDLLModuleExport" ascii wide
        $d4 = "MapModuleToMemory" ascii wide
        $d5 = "DynamicInvoke.Native.DELEGATES.NtCreateThreadEx" ascii wide
    condition:
        3 of them
}

rule Inceptor_Process_Injection_Syscall_Chain
{
    meta:
        description = "Detects Inceptor process injection chains using native syscalls"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "critical"
    strings:
        $s1 = "NtAllocateVirtualMemory" ascii wide
        $s2 = "NtWriteVirtualMemory" ascii wide
        $s3 = "NtProtectVirtualMemory" ascii wide
        $s4 = "NtCreateThreadEx" ascii wide
        $s5 = "OpenProcess" ascii wide
    condition:
        all of them
}

rule Inceptor_InstallUtil_RegAsm_Proxy_Execution
{
    meta:
        description = "Detects Inceptor proxy execution templates that use InstallUtil or RegAsm style loaders"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "high"
    strings:
        $p1 = "InstallUtil" ascii wide
        $p2 = "regasm" ascii wide
        $p3 = "DllRegisterServer" ascii wide
        $p4 = "DllUnregisterServer" ascii wide
        $p5 = "EntryPoint" ascii wide
    condition:
        3 of them
}

rule Inceptor_Unhook_NTDLL_Tradecraft
{
    meta:
        description = "Detects Inceptor unhooking workflows that remap ntdll and restore clean sections"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "critical"
    strings:
        $u1 = "UnhookNtdll" ascii wide
        $u2 = "NtOpenSection" ascii wide
        $u3 = "NtMapViewOfSection" ascii wide
        $u4 = "NtUnmapViewOfSection" ascii wide
        $u5 = "ntdll.dll" ascii wide
        $u6 = ".text" ascii wide
    condition:
        4 of them
}

rule Inceptor_SysWhispers_Direct_Syscalls
{
    meta:
        description = "Detects SysWhispers style direct syscall scaffolding used by Inceptor payloads"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "critical"
    strings:
        $w1 = "syswhispers" ascii wide
        $w2 = "GetSyscallStub" ascii wide
        $w3 = "NtAllocateVirtualMemory" ascii wide
        $w4 = "NtWriteVirtualMemory" ascii wide
        $w5 = "NtCreateThreadEx" ascii wide
        $w6 = "NtProtectVirtualMemory" ascii wide
    condition:
        4 of them
}

rule Inceptor_DInvoke_PE_Manual_Map_Extended
{
    meta:
        description = "Detects DInvoke PE manual mapping and section remap APIs exposed by Inceptor"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "high"
    strings:
        $m1 = "PE_MANUAL_MAP" ascii wide
        $m2 = "MapModuleFromDisk" ascii wide
        $m3 = "MapSection" ascii wide
        $m4 = "UnmapSection" ascii wide
        $m5 = "OverloadModule" ascii wide
        $m6 = "CallMappedPEModule" ascii wide
    condition:
        4 of them
}

rule Inceptor_AMSI_Session_Patch_Extended
{
    meta:
        description = "Detects extended AMSI patching and session manipulation markers used by Inceptor-style loaders"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "high"
    strings:
        $a1 = "AmsiOpenSession" ascii wide
        $a2 = "AmsiScanBuffer" ascii wide
        $a3 = "amsi.dll" ascii wide
        $a4 = "VirtualProtect" ascii wide
        $a5 = "RtlMoveMemory" ascii wide
        $a6 = "GetProcAddress" ascii wide
    condition:
        4 of them
}

rule Inceptor_APC_Remote_Thread_Tradecraft
{
    meta:
        description = "Detects APC and remote-thread execution chains commonly used in Inceptor payloads"
        author = "ShadowLab"
        source = "inceptor-main"
        severity = "critical"
    strings:
        $q1 = "NtQueueApcThread" ascii wide
        $q2 = "QueueUserAPC" ascii wide
        $q3 = "CreateRemoteThread" ascii wide
        $q4 = "RtlCreateUserThread" ascii wide
        $q5 = "NtWriteVirtualMemory" ascii wide
        $q6 = "OpenProcess" ascii wide
    condition:
        4 of them
}
