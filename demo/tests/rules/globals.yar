rule global_var_test {
    condition:
        my_global_var
}

rule global_int_test {
    condition:
        my_int > 100
}

rule global_str_test {
    condition:
        my_str == "expected_value"
}
