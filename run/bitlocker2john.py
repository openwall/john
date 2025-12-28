#!/usr/bin/env python3

# Usage: python3 bitlocker2john.py <bitlocker_image> -o <bitlocker_partition_offset>
# Supported modes:
# - $bitlocker$0$ and $bitlocker$1$ = VMK protected by a user password
# - $bitlocker$2$ and $bitlocker$3$ = VMK protected by a recovery key
# It is not possible to create a hash for VMKs protected by a TPM.
# Refs: https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc#encryption_methods

import argparse
import sys

BITLOCKER_SIGNATURE = '-FVE-FS-'
BITLOCKER_TO_GO_SIGNATURE = 'MSWIN4.1'
BITLOCKER_GUIDS = {'4967D63B-2E29-4AD8-8399-F6A339E3D001' : 'BitLocker', '4967D63B-2E29-4AD8-8399-F6A339E3D01' : 'BitLocker To Go', '92A84D3B-DD80-4D0E-9E4E-B1E3284EAED8' : 'BitLocker Used Disk Space Only'}
PROTECTION_TYPES = {0x0: 'VMK protected with clear key', 0x100: 'VMK protected with TPM', 0x200: 'VMK protected with startup key', 0x500: 'VMK protected with TPM and PIN', 0x800: 'VMK protected with recovery password', 0x2000: 'VMK protected with password'}
FVE_ENTRY_TYPES = {0x0: 'None', 0x2: 'VMK', 0x3: 'FVEK', 0x4: 'Validation', 0x6: 'Startup key', 0x7: 'Computer description', 0xb: 'FVEK backup', 0xf: 'Volume header block'}
FVE_VALUE_TYPES = {0x0: 'Erased', 0x1: 'Key', 0x2: 'UTF-16 string', 0x3: 'Stretch key', 0x4: 'Use key', 0x5: 'AES-CCM encrypted key', 0x6: 'TPM encoded key', 0x7: 'Validation', 0x8: 'VMK', 0x9: 'External key', 0xa: 'Update', 0xb: 'Error', 0xf: 'Offset and size'}
ITERATION_COUNT = 0x100000
BITLOCKER_PASSWORD_HASH_VERSIONS = [0,1]
BITLOCKER_RECOVERY_HASH_VERSIONS = [2,3]
HASHES = []

def guid_to_hex(guid):
    guid_parts = guid.split('-')

    search_target =  ''.join([guid_parts[0][i:i+2] for i in range(0, len(guid_parts[0]), 2)][::-1])
    search_target += ''.join([guid_parts[1][i:i+2] for i in range(0, len(guid_parts[1]), 2)][::-1])
    search_target += ''.join([guid_parts[2][i:i+2] for i in range(0, len(guid_parts[2]), 2)][::-1])
    search_target += guid_parts[3]
    search_target += guid_parts[4]

    return search_target

def hex_to_guid(hex_str):

    guid_parts = [0] * 5
    guid_parts[0] = hex_str[0:8]
    guid_parts[1] = hex_str[8:12]
    guid_parts[2] = hex_str[12:16]
    guid_parts[3] = hex_str[16:20]
    guid_parts[4] = hex_str[20:]

    guid  = ''.join([guid_parts[0][i:i+2] for i in range(0, len(guid_parts[0]), 2)][::-1])
    guid += '-'
    guid += ''.join([guid_parts[1][i:i+2] for i in range(0, len(guid_parts[1]), 2)][::-1])
    guid += '-'
    guid += ''.join([guid_parts[2][i:i+2] for i in range(0, len(guid_parts[2]), 2)][::-1])
    guid += '-'
    guid += guid_parts[3]
    guid += '-'
    guid += guid_parts[4]

    return guid.upper()

def uint_to_int(b):
    return int(b[::-1].hex(), 16)

# call in place of fp.read(), to stop reading out of bounds of file
def try_read_fp(fp, bytes_to_read):
    out = fp.read(bytes_to_read)
    if len(out) != bytes_to_read:
        print("Error reading out of bounds of file, exiting.", file=sys.stderr)
        sys.exit(1)

    return out

def parse_FVEK(fvek_data):
    print("\nParsing FVEK...", file=sys.stderr)
    nonce    = fvek_data[:12]
    mac      = fvek_data[12:28]
    enc_data = fvek_data[28:]

    print("Mac:", mac.hex(), file=sys.stderr)
    print("Nonce:", nonce.hex(), file=sys.stderr)
    print("Encrypted data:", enc_data.hex(), file=sys.stderr)

    return nonce, mac, enc_data

def parse_stretch_key(data):
    print("\nParsing stretch key...", file=sys.stderr)
    encryption_method = hex(uint_to_int(data[0:4]))
    salt = data[4:20]
    print("Encryption method:", encryption_method, file=sys.stderr)
    print("Salt:", salt.hex(), file=sys.stderr)
    current_pos = 0
    aes_ccm_data = data[20:]
    current_pos, data, value_type = parse_fve_metadata_entry(current_pos, aes_ccm_data)
    nonce, mac, enc_data = parse_aes_ccm_encrypted_key(data)

    return salt, nonce, mac, enc_data

def generate_hash(salt, nonce, mac, enc_data, protection_type):
    print("\nFound hash!", file=sys.stderr)
    if protection_type == 0x2000:
        versions = BITLOCKER_PASSWORD_HASH_VERSIONS
    if protection_type == 0x800:
        versions = BITLOCKER_RECOVERY_HASH_VERSIONS
    for version in versions:
        generated_hash = f"$bitlocker${version}${len(salt)}${salt.hex()}${ITERATION_COUNT}${len(nonce)}${nonce.hex()}${len(mac + enc_data)}${(mac + enc_data).hex()}"
        print(generated_hash)
        HASHES.append(generated_hash)

def parse_aes_ccm_encrypted_key(data):
    print("Parsing AES CCM key...", file=sys.stderr)
    nonce, mac, enc_data = parse_FVEK(data)
    return nonce, mac, enc_data

def parse_description(data):
    print("\nParsing description...", file=sys.stderr)
    print(f"Info: {data.decode('utf-16')}", file=sys.stderr)
    return

def parse_volume_header_block(data):
    print("\nParsing volume header block...", file=sys.stderr)
    block_offset = uint_to_int(data[0:8])
    block_size   = uint_to_int(data[8:16])
    print(f"Block offset: {hex(block_offset)}", file=sys.stderr)
    print(f"Block size: {block_size}", file=sys.stderr)

def parse_VMK(VMK_data):
    print("\nParsing VMK...", file=sys.stderr)
    guid = hex_to_guid(VMK_data[:16].hex())
    protection_type = uint_to_int(VMK_data[26:28])
    properties = VMK_data[28:]
    print("GUID:", guid, file=sys.stderr)
    print(f"Protection type: {hex(protection_type)} = {PROTECTION_TYPES.get(protection_type)}", file=sys.stderr)

    # only try parse properties if correct protection type
    protection_type_str = PROTECTION_TYPES.get(protection_type)
    if protection_type_str in ['VMK protected with password', 'VMK protected with recovery password']:
        current_pos = 28
        while current_pos < len(properties):
            current_pos, data, value_type = parse_fve_metadata_entry(current_pos, VMK_data[current_pos:])
            value_type_str = FVE_VALUE_TYPES.get(value_type)
            if value_type_str == 'Stretch key':
                salt, strech_nonce, stretch_mac, stretch_enc_data = parse_stretch_key(data)
            if value_type_str == 'AES-CCM encrypted key':
                nonce, mac, enc_data = parse_aes_ccm_encrypted_key(data)
                # salt is needed generating hash - with the assumption a stretch key will come before the CCM key so we have the salt
                generate_hash(salt, nonce, mac, enc_data, protection_type)

    return

def parse_fve_metadata_block(block):
    print('\nParsing FVE block...', file=sys.stderr)
    metadata_size = len(block)

    entry_size = uint_to_int(block[112:114])
    current_pos = 112
    while current_pos < metadata_size:
        current_pos, data, value_type = parse_fve_metadata_entry(current_pos, block[current_pos:current_pos+entry_size])
        fve_value_str = FVE_VALUE_TYPES.get(value_type)
        if fve_value_str == 'UTF-16 string':
            parse_description(data)
        if fve_value_str == 'AES-CCM encrypted key':
            parse_aes_ccm_encrypted_key(data)
        if fve_value_str == 'VMK':
            parse_VMK(data)
        if fve_value_str == 'Offset and size':
            parse_volume_header_block(data)

        try:
            entry_size = uint_to_int(block[current_pos:current_pos+2])
        except:
            return

def parse_fve_metadata_entry(current_pos, block):
    print("\nParsing FVE metadata entry...", file=sys.stderr)
    entry_size = uint_to_int(block[0:2])
    entry_type = uint_to_int(block[2:4])
    value_type = uint_to_int(block[4:6])
    version = hex(uint_to_int(block[6:8]))
    data = block[8:entry_size]

    print(f"Entry size: {entry_size}", file=sys.stderr)
    print(f"Entry type: {hex(entry_type)} = {FVE_ENTRY_TYPES.get(entry_type)}", file=sys.stderr)
    print(f"Value type: {hex(value_type)} = {FVE_VALUE_TYPES.get(value_type)}", file=sys.stderr)

    current_pos = current_pos + entry_size

    return current_pos, data, value_type


def parse_fve_metadata_header_data(header_data):
    signature = header_data[0:8]
    fve_metadata_header = header_data[64:64+48]
    metadata_size = parse_fve_metadata_header(fve_metadata_header)
    return metadata_size

def parse_fve_metadata_header(block):
    print("\nParsing FVE metadata header...", file=sys.stderr)
    metadata_size = uint_to_int(block[0:4])
    volume_guid = hex_to_guid(block[16:32].hex())
    nonce_counter = uint_to_int(block[32:36])
    encryption_method = hex(uint_to_int(block[36:40]))

    print("Metadata size:", metadata_size, file=sys.stderr)
    print("Volume GUID:", volume_guid, file=sys.stderr)
    print("Encryption method:", encryption_method, file=sys.stderr)

    return metadata_size

def main():

    p = argparse.ArgumentParser()
    p.add_argument('image_path', help="Path to encrypted BitLocker image")
    p.add_argument('-o', '--offset', help='Offset in image where BitLocker partition starts', default=0)
    args = p.parse_args()
    bitlocker_partition = args.image_path

    # to allow for hex offsets
    if type(args.offset) == str and args.offset.startswith('0x'):
        bitlocker_offset = int(args.offset, 16)
    else:
        bitlocker_offset = int(args.offset)

    with open(bitlocker_partition, 'rb') as fp:

        fp.seek(bitlocker_offset)
        boot_entry_point = try_read_fp(fp, 3)

        header = try_read_fp(fp, 8)
        if header.decode('latin-1') not in [BITLOCKER_SIGNATURE, BITLOCKER_TO_GO_SIGNATURE]:
            print("[!] Supplied image path is not a BitLocker partition. Try specifiying the offset of the BitLocker partition with -o", file=sys.stderr)
            exit()
        print(f'[+] BitLocker signature found: {header.decode()}', file=sys.stderr)
        sector_size = uint_to_int(try_read_fp(fp, 2))

        if header.decode('latin-1') == BITLOCKER_SIGNATURE:
            guid_offset = 0xa0
        if header.decode('latin-1') == BITLOCKER_TO_GO_SIGNATURE:
            guid_offset = 0x1a8

        fp.seek(guid_offset  + bitlocker_offset)
        volume_guid = try_read_fp(fp, 16)
        volume_guid = hex_to_guid(volume_guid.hex())
        volume_guid_id = BITLOCKER_GUIDS.get(volume_guid)
        if volume_guid_id == None:
            print("[!] Volume GUID not recognised. Exiting.", file=sys.stderr)
            sys.exit(1)
        print(f'[+] Identified volume GUID: {volume_guid} = {volume_guid_id}', file=sys.stderr)

        # get FVE metadata block addresses
        FVE_metadata_offsets = [hex(uint_to_int(try_read_fp(fp, 8)) + bitlocker_offset) for _ in range(3)]
        print(f'[+] FVE metadata info found at offsets {FVE_metadata_offsets}', file=sys.stderr)

        # all metadata blocks should be the same
        for f in FVE_metadata_offsets:

            fp.seek(int(f, 16))
            FVE_metadata_header = try_read_fp(fp, 64+48)
            FVE_metadata_size = parse_fve_metadata_header_data(FVE_metadata_header)

            fp.seek(int(f, 16))
            FVE_metadata_block = try_read_fp(fp, FVE_metadata_size)
            parse_fve_metadata_block(FVE_metadata_block)

            break

    if HASHES == []:
        print("\nNo hashes associated with the user password or recovery password found. Exiting...", file=sys.stderr)
    else:
        if sys.stdout.isatty():
            print("\nThe following hashes were found:")
        for bitlocker_hash in HASHES:
            print(bitlocker_hash)

    return


if __name__ == "__main__":
    main()
