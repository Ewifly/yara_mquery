rule{
    meta:
            author: "ewi"
            description : "nothing"
    strings:
        $s1 = "hello" nocase
        $s2 = "it's me" nocase
    condition:
        any of them
}