rule Find_NewJS_Array_Obfuscation

{
        meta:
            author = "David Ledbetter @Ledtech3"
            source = "Multi"
            description = "Rule to search for the new JS Obfuscation with the extra rounds of decoding."
            created = "2022-06-04"

        strings:
                $s0 = "'push'"
                $s1 = "'shift'"
                $s2 = "parseInt(_0x"
                $s3 = "document["
                $s4 = ") + _0x"

        condition:
                all of ($s*)

}
