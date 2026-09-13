rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR standard antivirus test file"
        author = "Sentinel"
        severity = "high"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar
}

rule Suspicious_Executable_In_Temp
{
    meta:
        description = "Detects executable written to Temp or Downloads with suspicious section names"
        author = "Sentinel"
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $upx0 = ".UPX0" ascii nocase
        $upx1 = ".UPX1" ascii nocase
        $themida = ".themida" ascii nocase
        $packed = ".packed" ascii nocase

    condition:
        $mz at 0 and any of ($upx0, $upx1, $themida, $packed)
}

rule Sentinel_Test_Payload
{
    meta:
        description = "Detects Sentinel live test payload"
        author = "Sentinel"
        severity = "high"

    strings:
        $sig = "SENTINEL-ANTIVIRUS-TEST-PAYLOAD-AUTONOMOUS-QUARANTINE" ascii

    condition:
        $sig
}

