rule Hunt_Excel_DNA_Built_XLL_Files

{
        meta:
            author = "David Ledbetter @Ledtech3"
            source = "https://twitter.com/c_APT_ure/status/1422974134854815751"
            description = "Hunt for Excel Addin dll files generated with Excel-DNA builder   https://excel-dna.net/"
            created = "2021-08-05"

        strings:
                $s0 = {45 00 78 00 63 00 65 00 6C 00 2D 00 44 00 4E 00 41 00}  //E.x.c.e.l.-.D.N.A.
                $magic = {4D 5A 90}

        condition:
                $magic at 0 and $s0

}
