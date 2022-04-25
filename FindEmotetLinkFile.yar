rule Find_Emotoet_LNK_File_VBS

{
        meta:
            author = "David Ledbetter"
            source = "https://twitter.com/Ledtech3/status/1518625978678927362"
            description = "Search for lnk files dropping vbs files."
            created = "2022-04-25"

        strings:
                $Header = {4C 00 00 00 01 14 02 00} 
                $s1 = "vbs" wide nocase          
                $s2 = "on error resume next"

        condition:
                $Header at 0 and all of ($s*)

}
