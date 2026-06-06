import "pe"

rule Windows_Credential_Dumping_Tool_Indicators
{
    meta:
        author = "asdasddqwdq29-a11y"
        description = "Detects a combination of credential-access commands and Windows security APIs"
        date = "2026-06-06"
        purpose = "Defensive static triage"

    strings:
        $cmd_1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd_2 = "lsadump::sam" ascii wide nocase
        $cmd_3 = "privilege::debug" ascii wide nocase
        $cmd_4 = "sekurlsa::minidump" ascii wide nocase

        $api_1 = "SamEnumerateUsersInDomain" ascii
        $api_2 = "LsaRetrievePrivateData" ascii
        $api_3 = "CryptUnprotectData" ascii
        $api_4 = "ReadProcessMemory" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.is_pe and
        filesize < 15MB and
        2 of ($cmd_*) and
        2 of ($api_*)
}

