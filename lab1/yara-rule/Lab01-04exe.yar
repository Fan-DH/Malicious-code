rule test
{
    strings:
        $string1 = "ADVAPI32"
        $string2 = "MSVCRT"
        $string3 = "KERNEL32"
        
        $string4  = "CreateRemoteThread"
        $string5  = "OpenProcess"
        $string6  = "GetCurrentProcess"
        $string7  = "FindResourceA"
        $string8  = "LoadResource"
        $string9  = "SizeofResource"
        $string10  = "AdjustTokenPrivileges"
        $string11  = "LookupPrivilegeValueA"
        $string12  = "OpenProcessToken"

        $string13  = "http://www.practicalmalwareanalysis.com/updater.exe"
        
    condition:
        filesize < 40KB
        and uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550

        and $string1 and $string2 and $string3 and $string4 and $string5 and $string6 and $string7 and $string8 and $string9 and $string10 and $string11 and $string12 and $string13 
}