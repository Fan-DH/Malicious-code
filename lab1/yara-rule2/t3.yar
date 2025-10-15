import "pe"
import "math"

rule test
{
    strings:
        $s1 = "GDI32"
        $s2 = "COMCTL32"
        $s3 = "SHELL32"

        $str = "C:\\BUG32\\jsc.exe"
        
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550

        and filesize > 3 * 1024 * 1024 and filesize < 3.1 * 1024 * 1024 

        and pe.imphash() == "d7ee0bec939bda9b20c9cb9dcb985e30" 

        and for any section in pe.sections :
            (section.name == ".rsrc" and 
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2)
        
        and $s1 and $s2 and $s3 and $str
   
}