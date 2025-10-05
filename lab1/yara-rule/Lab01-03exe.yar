rule test
{
    strings:
        $string1 = "OLEAUT32"
        $string2 = "MSVCRT"
        $string3 = "ole32"
        
        $string4 = "OleUninitialize"
        $string5 = "CoCreateInstance"
        $string6 = "OleInitialize"
        
    condition:
        filesize < 30KB
        and uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550

        and $string1 and $string2 and $string3 and $string4 and $string5 and $string6
}