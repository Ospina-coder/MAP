rule MAP_Innocuous_Smoke_Test : testing
{
    meta:
        description = "Innocuous MAP integration marker; not a malware signature"
        purpose = "testing_only"
        author = "MAP"
        version = "1"
    strings:
        $marker = "MAP_STATIC_ANALYSIS_INNOCUOUS_TEST_v1"
    condition:
        $marker
}
