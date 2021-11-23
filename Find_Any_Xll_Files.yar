rule Find_Any_Xll_Files

{
        meta:
            author = "David Ledbetter @Ledtech3"
            source = "https://twitter.com/James_inthe_box/status/1463144566941306880"
            description = "Find Any XLL File"
            created = "2021-11-23"

        strings:
                $Magic = {4D 5A 90}
                $s0 = "xlAutoOpen"

        condition:
                $Magic at 0 and $s0

}
