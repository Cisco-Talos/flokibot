import sys
import os
import argparse
import lib.lznt1

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False
    
try:
    import rc4
    HAVE_RC4 = True
except ImportError:
    HAVE_RC4 = False

def main(args, env):
    pe = pefile.PE(args.file)
    assert(len(pe.DIRECTORY_ENTRY_RESOURCE.entries) == 1)
    resource_dir =  pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
    resources = {}
    for res in resource_dir.directory.entries:
        name = str(res.name)
        assert(len(res.directory.entries) == 1)
        size = res.directory.entries[0].data.struct.Size
        offset = res.directory.entries[0].data.struct.OffsetToData
        data = pe.get_data(offset, size)
        resources[name] = data

    try:
        key = resources['KEY']
        CT = resources[args.resource]
        PT = rc4.rc4(CT, key)    # RC4 Decrypt Resource
        uncompressed = lib.lznt1.dCompressBuf(PT)    # LZNT1 Decompress
        payload_pe = pefile.PE(data=uncompressed)
        assert(len(payload_pe.get_warnings()) == 0)     # Verify uncompressed data is a valid PE
        payload_data = payload_pe.trim()
        with file(args.resource, "wb") as f:
            f.write(payload_data)
        print("Successfully Dumped payload {}".format(args.resource))
        exit()
    except Exception as e:
        print("Failed to dump payload {}".format(args.resource))
        return 1


def parse_args():
    parser = argparse.ArgumentParser(description = "Extract the payload from a Floki dropper binary")
    parser.add_argument("file", type = str, help = "Dropper executable")
    parser.add_argument("resource", choices = {"BOT32", "BOT64"}, help = "Which resource to extract")
    return parser.parse_args()


if __name__ == "__main__":
    if not HAVE_PEFILE:
        print "Please install pefile: pip install pefile"
        sys.exit(1)
    
    if not HAVE_RC4:
        print "Please install rc4: pip install rc4"
        sys.exit(1)

    res = main(parse_args(), os.environ)
    if res is not None:
        sys.exit(res)