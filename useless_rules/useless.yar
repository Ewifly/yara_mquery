rule pointless : useless {
    meta:
        author = "ewi"
        description = "pointless rule that matches pointless things"
    strings:
        $s1 = "pointless" nocase
        $s2 = "not useful" nocase
        $s3 = "boooooring" nocase
    condition:
        any of them
}

rule adelus : useless {
    meta:
        author = "ewi"
        description = "I was wondering"
    strings:
        $s1 = "hello" nocase
        $s2 = "it's me" nocase
    condition:
        any of them
}
