rule test
{
    strings:
        $string1 = "KERNEL32"
        $string2 = "MSVCRT"
        $string3 = "ADVAPI32"
        $string4 = "WININET"
        
        $string5  = "CreateMutexA"
        $string6  = "OpenMutexA"
        $string7  = "CreateThread"
        $string8  = "ExitProcess"
        $string9  = "InternetOpenUrlA"
        $string10  = "InternetOpenA"
        $string11  = "CreateWaitableTimerA"
        $string12  = "SetWaitableTimer"
        $string13  = "SystemTimeToFileTime"
        $string14 = "GetModuleFileNameA"
        
        $string15 = "http://www.malwareanalysisbook.com"
        
    condition:
        filesize < 100KB
        and uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550

        and $string1 and $string2 and $string3 and $string4 and $string5 and $string6 and $string7 and $string8 and $string9 and $string10 and $string11 and $string12 and $string13 and $string14 and $string15
}