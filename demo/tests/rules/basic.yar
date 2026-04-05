rule basic_rule {
    condition:
        true
}

rule simple_string {
    strings:
        $a = "hello"
    condition:
        $a
}

rule case_insensitive {
    strings:
        $a = "WORLD" nocase
    condition:
        $a
}

rule multiple_strings {
    strings:
        $a = "foo"
        $b = "bar"
        $c = "baz"
    condition:
        any of them
}
