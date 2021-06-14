rule{
    meta:
            author: "ewi"
            description : "pointless"
    strings:
        $s1 = "pointless" nocase
        $s2 = "not useful" nocase
    condition:
        any of them
}