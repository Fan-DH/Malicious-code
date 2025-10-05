rule test
{
    strings:
        $string1 = "KERNEL32"
        $string2 = "MSVCRT"
        $string3 = "WS2_32"
        
        $string4 = "CreateMutexA"
        $string5 = "OpenMutexA"
        $string6 = "CreateProcessA"
        $string7 = "Sleep"
        
        $string8 = "127.26.152.13"

    condition:
        filesize < 200KB
        and uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550

        and $string1 and $string2 and $string3
        and $string4 and $string5 and $string6 and $string7
        and $string8 
}