rule Windows_LSASS_Minidump_Artifact
{
    meta:
        author = "asdasddqwdq29-a11y"
        description = "Detects a Windows minidump containing an LSASS process path"
        date = "2026-06-06"
        purpose = "Defensive artifact triage"

    strings:
        $lsass_path = "System32\\lsass.exe" wide nocase
        $lsass_name = "lsass.exe" wide nocase

    condition:
        uint32(0) == 0x504d444d and
        1 of ($lsass_*)
}

