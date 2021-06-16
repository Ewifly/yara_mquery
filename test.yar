rule adelus {
    meta:
            author = "ewi"
            description = "I was wondering"
    strings:
        $s1 = "hello" nocase
        $s2 = "it's me" nocase
    condition:
        any of them
}
