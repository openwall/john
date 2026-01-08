#!/usr/bin/env python3

# Usage: python3 fvde2john.py <image_file>
# The partition table is parsed to find the boot volume, often named 'Recovery HD'. The boot volume can be identified by its type GUID: 426F6F74-0000-11AA-AA11-00306543ECAC.
# The boot volume contains a file called `EncryptedRoot.plist.wipekey`. This is stored on the volume at `/com.apple.boot.X/System/Library/Caches/com.apple.corestorage/EncryptedRoot.plist.wipekey`, where `X` is variable but is often `P` or `R`. This plist file is encrypted with AES-XTS; the key is found in the CoreStorage volume header, and the tweak is b'\x00' * 16.
# The decrypted plist contains information relating to the user(s). This includes the salt, kek and iterations required to construct the hash as well as information such as username and password hints (if present).
# For non-system drives, the plist file is found in the encrypted metadata, in block type 0x19.

import plistlib
import os
import argparse
import sys
import re
import base64
import zlib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.stderr.write("cryptography is missing, run 'pip install --user cryptography' to install it!\n")
    sys.exit(1)
try:
    import pytsk3
except ImportError:
    sys.stderr.write("pytsk3 is missing, run 'pip install --user pytsk3' to install it!\n")
    sys.exit(1)

HEX_CORE_STORAGE_TYPE_GUID = '53746F72-6167-11AA-AA11-00306543ECAC'
HEX_APPLE_BOOT_STORAGE_TYPE_GUID = '426F6F74-0000-11AA-AA11-00306543ECAC'
LOCAL_USER_TYPE_ID = [0x10060002, 0x10000001] # added 0x10000001 for removable drives
BOOT_DIR_REGEX = re.compile(r'com.apple.boot.(?P<boot_letter>[A-Z])')

# long regex for CryptoUsers dict (removable drives only) because difficult to parse with plistlib
CRYPTO_USERS_REGEX_STR  = r'<key>CryptoUsers<\/key>.*?'
for EntryName in ["PassphraseWrappedKEKStruct", "WrapVersion", "UserType", "UserIdent",
                  "UserNamesData", "PassphraseHint", "KeyEncryptingKeyIdent", "UserFullName", "EFILoginGraphics"]:
    CRYPTO_USERS_REGEX_STR += r'<key>' + EntryName + r'<\/key><.*?>(?P<' + EntryName + r'>.*?)(<.*?>)*?'
CRYPTO_USERS_REGEX_STR += r'<.*?>'
CRYPTO_USERS_REGEX   = re.compile(CRYPTO_USERS_REGEX_STR)

def uint_to_int(b):
    return int(b[::-1].hex(), 16)

def guid_to_hex(guid):
    guid_parts = guid.split('-')

    hex_str  = ''.join([guid_parts[0][i:i+2] for i in range(0, len(guid_parts[0]), 2)][::-1])
    hex_str += ''.join([guid_parts[1][i:i+2] for i in range(0, len(guid_parts[1]), 2)][::-1])
    hex_str += ''.join([guid_parts[2][i:i+2] for i in range(0, len(guid_parts[2]), 2)][::-1])
    hex_str += guid_parts[3]
    hex_str += guid_parts[4]

    return hex_str.lower()

# call in place of fp.read(), to stop reading out of bounds of file
def try_read_fp(fp, bytes_to_read):
    out = fp.read(bytes_to_read)
    if len(out) != bytes_to_read:
        sys.stderr.write("Error reading out of bounds of file, exiting.\n")
        sys.exit(1)

    return out

def parse_partition_table(fp):
    # determine whether sector size is 0x200 or 0x1000
    sector_size = 0x0

    # look for EFI PART at start of sector 1
    fp.seek(0x200)
    signature = try_read_fp(fp, 0x8)
    if signature == b'EFI PART':
        sector_size = 0x200

    else:
        fp.seek(0x1000)
        signature = try_read_fp(fp, 0x8)
        if signature == b'EFI PART':
            sector_size = 0x1000

    if not sector_size:
        sys.stderr.write(f"[!] Invalid sector size {sector_size} (not 512 or 4096 bytes). Exiting.\n")
        sys.exit(1)

    fp.seek(2 * sector_size) # go to sector 2
    partitions = []
    partition_entry = b'1'
    while any(partition_entry):
        partition_entry = try_read_fp(fp, 0x80)
        if any(partition_entry):
            partitions.append(partition_entry)

    partition_dict = {}
    for p in partitions:
        part_GUID, type_GUID, start, partition_name = parse_partition_entry(p)
        sp = uint_to_int(start) * sector_size
        partition_dict[part_GUID.hex()] = {'start':sp, 'partition_type':type_GUID.hex(), 'partition_name':partition_name.decode('utf-16').strip('\x00')}

    return partition_dict

def findall(p, s):
    i = s.find(p)
    while i != -1:
        yield i
        i = s.find(p, i+1)

def parse_partition_entry(partition_entry):
    type_GUID = partition_entry[0:0x10]
    part_GUID = partition_entry[0x10:0x20]
    start_LBA = partition_entry[0x20:0x28]
    partition_name = partition_entry[0x38:0x80]
    return part_GUID, type_GUID, start_LBA, partition_name

def parse_corestorage_header(fp, start_pos):
    fp.seek(start_pos)
    cs_header = try_read_fp(fp, 0x200) # Physical volume header is 512 bytes
    physical_volume_size = cs_header[64:72]
    cs_signature = cs_header[88:90]
    assert cs_signature == b'CS'

    block_size = uint_to_int(cs_header[96:100])
    metadata_block_numbers = cs_header[104:136] # array of 4x8 metadata block numbers
    offsets = [uint_to_int(metadata_block_numbers[start: start+8]) for start in range(0, 32, 8)]

    aes_key = cs_header[176:192]
    physical_UUID = cs_header[304:320]
    logical_UUID  = cs_header[320:336]
    return aes_key, offsets, block_size, physical_UUID

def AES_XTS_decrypt(aes_key1, aes_key2, tweak, ct):
    decryptor = Cipher(
        algorithms.AES(key=aes_key1 + aes_key2),
        modes.XTS(tweak=tweak),
    ).decryptor()
    pt = decryptor.update(ct)
    return pt

def AES_XTS_decrypt_metadata_block(aes_key1, aes_key2, block_number, enc_metadata):
    block_start = block_number * 8192
    block_end = block_start + 8192

    # tweak = block number
    tweak = hex(block_number)[2:].zfill(32)
    tweak = bytearray.fromhex(tweak)[::-1]

    decrypted_block = AES_XTS_decrypt(aes_key1, aes_key2, tweak, enc_metadata[block_start:block_end])
    return decrypted_block

def parse_keybag_entry(uuid, pt):
    uuid_iterator = findall(uuid, pt)
    for sp in uuid_iterator:
        ke_uuid, ke_tag, ke_keylen = pt[sp:sp+16], uint_to_int(pt[sp + 16:sp + 18]), uint_to_int(pt[sp + 18:sp + 20])
        padding = pt[sp + 20:sp + 24]
        keydata = pt[sp + 24: sp + 24 + ke_keylen]

        # only tag 3 is needed for constructing the hash
        if ke_tag == 3:
            assert padding == b'\x00\x00\x00\x00'
            return keydata

    return None

def get_all_partitions_of_type(partition_dict, part_type):
    return [partition_dict[p]['start'] for p in partition_dict if partition_dict[p]['partition_type'] == guid_to_hex(part_type)]

def load_plist_dict(pt):
    # resultant pt has one extra malformed line in the xml, so we remove this.
    plist_str = b''.join(pt.split(b'\n')[:-1]).decode()
    d = plistlib.loads(plist_str)
    return d

# get upper directory name e.g. com.apple.boot.P
def get_boot_dir(fs_object):
    for entry in fs_object.open_dir():
        entry_name = entry.info.name.name.decode()
        if re.match(BOOT_DIR_REGEX, entry_name):
            return entry_name
    return None

def recover_file(fs_object, file_path):
    file_obj = fs_object.open(file_path)
    size = file_obj.info.meta.size
    offset = 0
    data = file_obj.read_random(offset, size)
    return data

def get_EncryptedRoot_plist_wipekey(image_file, start_pos):
    img = pytsk3.Img_Info(image_file)
    fs = pytsk3.FS_Info(img, offset=start_pos)
    boot_dir = get_boot_dir(fs)

    if boot_dir:
        file_path = os.path.join(f"{boot_dir}/System/Library/Caches/com.apple.corestorage/EncryptedRoot.plist.wipekey")
        EncryptedRoot_data = recover_file(fs, file_path)

    else:
        # EncryptedRoot.plist.wipekey not found in image file, will search metadata blocks for encryption context plist
        return None

    return EncryptedRoot_data

def construct_fvde_hash(PassphraseWrappedKEKStruct):
    salt = PassphraseWrappedKEKStruct[8:24]
    kek  = PassphraseWrappedKEKStruct[32:56]
    iterations = uint_to_int(PassphraseWrappedKEKStruct[168:172])
    fvde_hash = f"$fvde$1${len(salt)}${salt.hex()}${iterations}${kek.hex()}"

    return fvde_hash

def format_hash_str(user_part):
    if user_part == None:
        return ''
    # remove colons so that hash format is consistent and strip newlines
    return user_part.replace("\n","").replace("\r","").replace(":","")

def parse_metadata_block(metadata_block):
    metadata_block_header = metadata_block[:64] # metadata block header is 64 bytes
    metadata_block_data = metadata_block[64:]

    block_type, block_size, possibly_lvfwiped = parse_metadata_block_header(metadata_block_header)

    if block_type == 0x11:
        volume_group_xml_offset, volume_group_xml_size, volume_groups_descriptor_offset = parse_metadata_block_0x11(metadata_block_data)

    return volume_group_xml_offset, volume_group_xml_size, volume_groups_descriptor_offset

# return block_type so we know what to parse
def parse_metadata_block_header(metadata_block_header):
    crc32 = metadata_block_header[0:4]
    possibly_lvfwiped = metadata_block_header[0:8] # have seen lvfwiped here, the rest of the block is zero
    version = uint_to_int(metadata_block_header[8:10])
    block_type = uint_to_int(metadata_block_header[10:12])
    block_size = uint_to_int(metadata_block_header[48:52])

    return block_type, block_size, possibly_lvfwiped

def parse_metadata_block_0x11(metadata_block):
    metadata_size                   = uint_to_int(metadata_block[0:4])
    volume_groups_descriptor_offset = uint_to_int(metadata_block[156:160])
    volume_group_xml_offset         = uint_to_int(metadata_block[160:164])
    volume_group_xml_size           = uint_to_int(metadata_block[164:168])

    return volume_group_xml_offset, volume_group_xml_size, volume_groups_descriptor_offset

def parse_metadata_block_0x19(metadata_block):
    compressed_data_size = uint_to_int(metadata_block[40:44])
    uncompressed_data_size = uint_to_int(metadata_block[44:48])
    xml_plist_data_offset = uint_to_int(metadata_block[48:52])
    xml_plist_data_size   = uint_to_int(metadata_block[52:56])
    xml_plist = metadata_block[xml_plist_data_offset - 64: xml_plist_data_offset + xml_plist_data_size - 64]

    if compressed_data_size < uncompressed_data_size:
        xml_plist = decompress_xml_plist(xml_plist)

    return xml_plist

def parse_volume_group_descriptor(volume_group_descriptor):
    enc_metadata_size = uint_to_int(volume_group_descriptor[8:16]) # in no. of blocks
    primary_enc_metadata_block_no = uint_to_int(volume_group_descriptor[32:38])
    plist_data = volume_group_descriptor[48:]

    return primary_enc_metadata_block_no, enc_metadata_size

def parse_CryptoUsers_dict(CryptoUsers_dict, EncryptedRoot):
    for user_index in range(len(CryptoUsers_dict)):
        # We want the local user login details i.e. not iCloud
        if CryptoUsers_dict[user_index].get('UserType') in LOCAL_USER_TYPE_ID:
            passphrase_hint = CryptoUsers_dict[user_index].get('PassphraseHint')

            name_info = CryptoUsers_dict[user_index].get('UserNamesData')
            full_name_info = ''
            username_info  = ''
            if len(name_info) == 2:
                full_name_info, username_info = name_info[0].decode(), name_info[1].decode()

            full_name_info = format_hash_str(full_name_info)
            passphrase_hint = format_hash_str(passphrase_hint)

            # Hash info stored in the PassphraseWrappedKEKStruct in decrypted plist
            # Stored in base64 in metadata block plist, but already decoded in EncryptedRoot plist
            PassphraseWrappedKEKStruct = CryptoUsers_dict[user_index].get('PassphraseWrappedKEKStruct')
            if not EncryptedRoot:
                PassphraseWrappedKEKStruct = base64.b64decode(PassphraseWrappedKEKStruct)
            fvde_hash = construct_fvde_hash(PassphraseWrappedKEKStruct)
            sys.stdout.write(f"{username_info}:{fvde_hash}:::{full_name_info} {passphrase_hint}::\n")
    return

def decompress_xml_plist(xml_plist):
    # sometimes the xml plist in metadata block type 0x19 is compressed with zlib
    try:
        decompressed_xml_plist = zlib.decompress(xml_plist)
        return decompressed_xml_plist
    except zlib.error:
            sys.stderr.write("[!] Zlib decompression error, exiting.\n")
            sys.exit(1)


def get_CryptoUsers_dict_from_EncryptedRoot(EncryptedRoot_data, aes_key1):
    aes_key2 = b'\x00' * 16
    tweak = b'\x00' * 16
    pt = AES_XTS_decrypt(aes_key1, aes_key2, tweak, EncryptedRoot_data)
    CryptoUsers_dict = load_plist_dict(pt)['CryptoUsers']

    return CryptoUsers_dict

def get_CryptoUsers_dict_from_encrypted_metadata(cs_start_pos, offsets, block_size, fp, physical_UUID, aes_key1):
    o = offsets[0] # all metadata blocks equal so just use first
    metadata_block_start = cs_start_pos + o * block_size
    fp.seek(metadata_block_start)
    metadata_block = try_read_fp(fp, 0x200)

    volume_group_xml_offset, volume_group_xml_size, volume_groups_descriptor_offset = parse_metadata_block(metadata_block)
    fp.seek(metadata_block_start + volume_group_xml_offset)
    xml = try_read_fp(fp, volume_group_xml_size)

    fp.seek(metadata_block_start + volume_groups_descriptor_offset)
    volume_group_descriptor = try_read_fp(fp, 0x200)
    primary_enc_metadata_block_no, enc_metadata_size = parse_volume_group_descriptor(volume_group_descriptor)

    fp.seek(cs_start_pos + primary_enc_metadata_block_no * block_size)
    enc_metadata = try_read_fp(fp, enc_metadata_size * block_size)

    for block_number in range(0, enc_metadata_size):
        aes_key2 = physical_UUID

        decrypted_block = AES_XTS_decrypt_metadata_block(aes_key1, aes_key2, block_number, enc_metadata)
        decrypted_metadata_block_header = decrypted_block[:64]
        block_type, metadata_block_size, possibly_lvfwiped = parse_metadata_block_header(decrypted_metadata_block_header)

        # data block is wiped, skip
        if possibly_lvfwiped == b'LVFwiped':
            continue

        # iterate through blocks until find block_type 0x19 - containing encryption context
        if block_type == 0x19:
            xml_plist = parse_metadata_block_0x19(decrypted_block[64:metadata_block_size]).decode()

            matches = []
            for m in re.finditer(CRYPTO_USERS_REGEX, xml_plist):
                matches.append(m.groupdict())

            if matches:
                CryptoUsers_dict = {}
                for user_index in range(len(matches)):
                    CryptoUsers_dict[user_index] = matches[user_index]
                    # if present convert user type from string to hex
                    user_type = CryptoUsers_dict[user_index].get('UserType')
                    if user_type:
                        CryptoUsers_dict[user_index]['UserType'] = int(CryptoUsers_dict[user_index]['UserType'], 16)

                return CryptoUsers_dict

def main():

    p = argparse.ArgumentParser()
    p.add_argument('image_file')
    args = p.parse_args()
    image_file = args.image_file

    with open(image_file, 'rb') as fp:
        partition_dict = parse_partition_table(fp)

        core_storage_volumes = get_all_partitions_of_type(partition_dict, HEX_CORE_STORAGE_TYPE_GUID)
        if core_storage_volumes == []:
            sys.stderr.write("[!] No CoreStorage volumes found, exiting.\n")
            sys.exit(1)
        boot_volumes = get_all_partitions_of_type(partition_dict, HEX_APPLE_BOOT_STORAGE_TYPE_GUID)

        # Unlikely to have more than one boot volume, but loop anyway
        for boot_start_pos in boot_volumes:
            EncryptedRoot_data = get_EncryptedRoot_plist_wipekey(image_file, boot_start_pos)
            for cs_start_pos in core_storage_volumes:
                aes_key1, offsets, block_size, physical_UUID = parse_corestorage_header(fp, cs_start_pos)
                if EncryptedRoot_data:
                    CryptoUsers_dict = get_CryptoUsers_dict_from_EncryptedRoot(EncryptedRoot_data, aes_key1)
                else:
                    CryptoUsers_dict = get_CryptoUsers_dict_from_encrypted_metadata(cs_start_pos, offsets, block_size, fp, physical_UUID, aes_key1)

                parse_CryptoUsers_dict(CryptoUsers_dict, EncryptedRoot_data)

            return


if __name__ == "__main__":
    main()
