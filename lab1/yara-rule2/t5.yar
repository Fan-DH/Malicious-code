import "pe"
import "math"

rule test
{
    strings:
        $s1 = "WINMM"
        $s2 = "SHELL32"
        $s3 = "SHLWAPI"

        $str = "C:\\Program Files\\mrsmajor\\mrsmjrgui.exe"
        
    condition:

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550

        and filesize > 1.9 * 1024 * 1024 and filesize < 2 * 1024 * 1024 

        and pe.imphash() == "d7ee0bec939bda9b20c9cb9dcb985e30" 

        and for any section in pe.sections :
            (section.name == ".rsrc" and 
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.8)

        and $s1 and $s2 and $s3 and $str
   
}