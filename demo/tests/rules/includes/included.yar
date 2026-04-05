rule test_rule {
    strings:
        $a = "include_test"
    condition:
        $a
}
