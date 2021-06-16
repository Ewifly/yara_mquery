rule pointless{
    meta:
            author = "ewi"
            description = "pointless rule"
    strings:
        $s1 = "pointless" nocase
        $s2 = "not useful" nocase
    condition:
        any of them
}
