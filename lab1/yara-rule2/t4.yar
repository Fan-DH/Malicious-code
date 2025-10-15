import "pe"
import "math"

rule test
{
    strings:
        $s1 = "WINMM"
        $s2 = "SHELL32"
        $s3 = "WS2_32"
        
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550

        and filesize > 2.4 * 1024 * 1024 and filesize < 2.5 * 1024 * 1024 

        and pe.imphash() == "a48ac089b76f7d9126bf1cef67ed7e6f" 

        and pe.entry_point == 458034

        and for any section in pe.sections :
            (section.name == ".rdata" and 
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.3)
        
        and $s1 and $s2 and $s3
}