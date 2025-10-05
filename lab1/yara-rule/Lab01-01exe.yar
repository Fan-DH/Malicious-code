rule test
{
    strings:
        $string1 = "KERNEL32"
        $string2 = "MSVCRT"
        $string3 = "Lab01-01"

        $string4 = "CreateFileA"
        $string5 = "CopyFileA"
        $string6 = "CreateFileMappingA"
        $string7 = "MapViewOfFile"
        $string8 = "UnmapViewOfFile"
        $string9 = "FindClose"
        $string10 = "FindFirstFileA"
        $string11 = "FindNextFileA"
        
        $string12 = "kerne132.dll"
        $string13 = "WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"
        
    condition:
        filesize < 100KB
        and uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and $string1 and $string2 and $string3 and $string4 and $string5 and $string6 and $string7 and $string8 and $string9 and $string10 and $string11 and $string12 and $string13
}