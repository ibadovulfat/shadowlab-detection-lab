rule Memory_AMSI_ETW_Patch_Sequence
{
    meta:
        description = "Detects in-memory AMSI and ETW patching marker sequence"
        author = "ShadowLab"
        severity = "critical"
        scope = "memory"
    strings:
        $a1 = "amsi.dll" ascii wide
        $a2 = "AmsiScanBuffer" ascii wide
        $a3 = "EtwEventWrite" ascii wide
        $a4 = "VirtualProtect" ascii wide
        $a5 = "RtlMoveMemory" ascii wide
    condition:
        4 of them
}

rule Memory_Manual_Map_Remap
{
    meta:
        description = "Detects reflective mapping and remap workflows in memory dumps"
        author = "ShadowLab"
        severity = "high"
        scope = "memory"
    strings:
        $m1 = "MapModuleToMemory" ascii wide
        $m2 = "MapModuleFromDisk" ascii wide
        $m3 = "MapSection" ascii wide
        $m4 = "UnmapSection" ascii wide
        $m5 = "CallMappedPEModule" ascii wide
        $m6 = "CallMappedDLLModuleExport" ascii wide
    condition:
        4 of them
}

rule Memory_Syscall_Apc_Injection
{
    meta:
        description = "Detects APC or remote thread injection via native APIs in memory"
        author = "ShadowLab"
        severity = "critical"
        scope = "memory"
    strings:
        $s1 = "NtQueueApcThread" ascii wide
        $s2 = "QueueUserAPC" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
        $s4 = "RtlCreateUserThread" ascii wide
        $s5 = "NtCreateThreadEx" ascii wide
        $s6 = "NtWriteVirtualMemory" ascii wide
    condition:
        4 of them
}
