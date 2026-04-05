rule regex_simple {
    strings:
        $re = /test.*pattern/
    condition:
        $re
}

rule regex_case_insensitive {
    strings:
        $re = /HELLO/i
    condition:
        $re
}

rule regex_complex {
    strings:
        $re = /[a-z]+@[a-z]+\.[a-z]{2,}/
    condition:
        $re
}
