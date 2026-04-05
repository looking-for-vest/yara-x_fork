rule hex_pattern {
    strings:
        $hex = { 48 65 6C 6C 6F }
    condition:
        $hex
}

rule hex_with_jumps {
    strings:
        $hex = { 48 [2-5] 6F }
    condition:
        $hex
}

rule hex_wildcard {
    strings:
        $hex = { 48 ?? 6C 6F }
    condition:
        $hex
}
