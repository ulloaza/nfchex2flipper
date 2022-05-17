#!/usr/bin/env python

import codecs
import copy
import sys
from collections import defaultdict

from bitstring import BitArray

if len(sys.argv) == 2:
    sys.exit('''
------------------
Usage: dump2flipper.py <dump.nfc> <flipper.nfc>
Mifare dumps reader.
''')

def hex_split(raw):
     raw = " ".join(raw[i:i+2] for i in range(0, len(raw), 2))
     return raw

def print_info(args, data):
    out = open(args[1], "x")
    blocksmatrix = []
    blockrights = {}
    block_number = 0

    data_size = len(data)

    if data_size not in {4096, 1024, 320}:
        sys.exit("Wrong file size: %d bytes.\nOnly 320, 1024 or 4096 bytes allowed." % len(data))

    print("Read OK...")
    # read all sectors
    sector_number = 0
    start = 0
    end = 64
    while True:
        sector = data[start:end]
        sector = codecs.encode(sector, 'hex')
        if not isinstance(sector, str):
            sector = str(sector, 'ascii')
        sectors = [sector[x:x + 32] for x in range(0, len(sector), 32)]

        blocksmatrix.append(sectors)

        # after 32 sectors each sector has 16 blocks instead of 4
        sector_number += 1
        if sector_number < 32:
            start += 64
            end += 64
        elif sector_number == 32:
            start += 64
            end += 256
        else:
            start += 256
            end += 256

        if start == data_size:
            break

    blocksmatrix_clear = copy.deepcopy(blocksmatrix)

    # Convert to hex format
    uid = blocksmatrix[0][0][0:8]
    uid = hex_split(uid)
    bcc = blocksmatrix[0][0][8:10]
    bcc = hex_split(bcc)
    sak = blocksmatrix[0][0][10:12]
    sak = hex_split(sak)
    atqa = blocksmatrix[0][0][12:14]
    atqa = hex_split(atqa)

    print("\n\tUID:  " + blocksmatrix[0][0][0:8])
    print("\tBCC:  " + blocksmatrix[0][0][8:10])
    print("\tSAK:  " + blocksmatrix[0][0][10:12])
    print("\tATQA: " + blocksmatrix[0][0][12:14])

    print("\n\nFile size: %d bytes. Expected %d sectors" % (len(data), sector_number))
    with open(args[1], 'w') as out:
        # Supply NFC file header
        out.write('Filetype: Flipper NFC device\n')
        out.write('Version: 2\n')
        out.write('# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card\n')
        out.write('Device type: Mifare Classic\n')
        out.write('# UID, ATQA and SAK are common for all formats\n')
        out.write("UID: " + str(uid))
        out.write("\nATQA: " + str(sak))
        out.write("\nSAK: " + str(sak))
        out.write('\n# Mifare Classic specific data\n')
        out.write('Mifare Classic type: 1K\n')
        out.write('# Mifare Classic blocks')

        for q in range(0, len(blocksmatrix)):
            n_blocks = len(blocksmatrix[q])
            # z is the block in each sector
            for z in range(0, len(blocksmatrix[q])):
                block_data = blocksmatrix[q][z]
                block_data = hex_split(block_data)
                out.write("\nBlock " + str(block_number) + ": " + str(block_data))
                block_number += 1

def main(args):
    filename = args[0]
    print("Opening" + filename)
    with open(filename, "rb") as f:
        data = f.read()
        print_info(args, data)

if __name__ == "__main__":
    main(sys.argv[1:])