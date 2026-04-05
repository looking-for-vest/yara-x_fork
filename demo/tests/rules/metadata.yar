rule metadata_test {
    meta:
        author = "Test Author"
        version = 1
        enabled = true
        ratio = 3.14
    strings:
        $a = "metadata"
    condition:
        $a
}

rule multiple_metadata {
    meta:
        author = "Another Author"
        description = "Test rule with multiple metadata"
        severity = "high"
        count = 100
    condition:
        true
}
