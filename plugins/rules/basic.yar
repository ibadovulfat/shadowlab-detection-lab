
rule Suspicious_Strings {
    meta:
        description = "Detects common suspicious strings in memory"
        author = "ShadowLab"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "cmd.exe /c" nocase
        $s4 = "eval("
    condition:
        any of them
}

rule Shellcode_Pattern {
    meta:
        description = "Simple shellcode-like NOP sled pattern"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}
