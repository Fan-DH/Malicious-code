import "pe"
import "math"

rule test
{
    strings:

        $s1 = "KERNEL32"
        $s2 = "MSVCRT"
        $s3 = "ADVAPI32"
        $s4 = "USER32" 

        $string = "WANACRY!"
        
    condition:

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550

        and pe.version_info["OriginalFilename"] == "diskpart.exe"

        and filesize > 3 * 1024 * 1024 and filesize < 3.5 * 1024 * 1024 

        and pe.imphash() == "68f013d7437aa653a8a98a05807afeb1" 

        and pe.entry_point == 30650

        and for any section in pe.sections :
            (section.name == ".rsrc" and 
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.5)

        and $s1 and $s2 and $s3 and $s4 and $string
}