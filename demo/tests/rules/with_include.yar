include "includes/included.yar"

rule main_rule {
    strings:
        $b = "main_pattern"
    condition:
        $b or test_rule
}
