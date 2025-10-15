import "pe"
import "math"

rule test
{
    strings:

        $s1 = "WINMM"
        $s2 = "WINSPOOL"
        $s3 = "WS2_32"
        
    condition:

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550

        and filesize > 39 * 1024 * 1024 and filesize < 40 * 1024 * 1024 

        and pe.imphash() == "16bbc4f208c0c35e9da04bf394aa9737" 

        and pe.entry_point == 750724

        and for any section in pe.sections :
            (section.name == ".rdata" and 
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.5)

        and $s1 and $s2 and $s3 
}