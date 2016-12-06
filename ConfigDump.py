import os
import pefile
import re
import struct
import argparse
import sys

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

def main(args, env):
    pe = pefile.PE(args.file)
    filedata = pe.trim()
    
    # Regex for finding function the deobfuscates config data.
    restr = "\x56\xba(.{2})\x00\x00\x52\x68(.{4})"
    try:
        reobj = re.search(restr, filedata, re.DOTALL)
        configLength = struct.unpack("<H", reobj.groups(1)[0])[0]
        configOffset = struct.unpack("<I", reobj.groups(1)[1])[0]
        obfConfig = pe.get_data(configOffset - pe.OPTIONAL_HEADER.ImageBase, configLength)
        
        # XOR Key is at the beginning of the 3rd PE section
        try:
            thirdsection = pe.sections[2]
            xorkey = pe.get_data(thirdsection.VirtualAddress, configLength)
        except:
            print("Failed to fetch third PE section of {}".format(args.file))
        
        configData = "".join(chr(ord(obfConfig[i]) ^ ord(xorkey[i])) for i in range(configLength))
        with file("config.bin", "wb") as f:
            f.write(configData)            
        url = re.findall("http[^\x00]*",configData)[0].replace(".","[.]")
        print("Successfully dumped config.bin.\nURL: {}".format(url))
        return 0
    except:
        print("Failed to extract Config block")
        return 1

def parse_args():
    parser = argparse.ArgumentParser(description = "Extract the config data from a 32 bit Floki payload binary")
    parser.add_argument("file", type = str, help = "BOT32 File extracted from PayloadDump")
    return parser.parse_args()


if __name__ == "__main__":
    if not HAVE_PEFILE:
        print "Please install pefile: pip install pefile"
        sys.exit(1)

    res = main(parse_args(), os.environ)
    if res is not None:
        sys.exit(res)