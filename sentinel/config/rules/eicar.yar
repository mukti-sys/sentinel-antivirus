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

