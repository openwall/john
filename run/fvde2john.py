#!/usr/bin/env python3

# Usage: python3 fvde2john.py <image_file>
# The partition table is parsed to find the boot volume, often named 'Recovery HD'. The boot volume can be identified by its type GUID: 426F6F74-0000-11AA-AA11-00306543ECAC.
# The boot volume contains a file called `EncryptedRoot.plist.wipekey`. This is stored on the volume at `/com.apple.boot.X/System/Library/Caches/com.apple.corestorage/EncryptedRoot.plist.wipekey`, where `X` is variable but is often `P` or `R`. This plist file is encrypted with AES-XTS; the key is found in the CoreStorage volume header, and the tweak is b'\x00' * 16.
# The decrypted plist contains information relating to the user(s). This includes the salt, kek and iterations required to construct the hash as well as information such as username and password hints (if present).

import plistlib
import os
import argparse
import sys
import re

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.stderr.write("cryptography is missing, run 'pip install --user cryptography' to install it!")
    sys.exit(1)
try:
    import pytsk3
except ImportError:
    sys.stderr.write("pytsk3 is missing, run 'pip install --user pytsk3' to install it!")
    sys.exit(1)

HEX_CORE_STORAGE_TYPE_GUID = '53746F72-6167-11AA-AA11-00306543ECAC'
HEX_APPLE_BOOT_STORAGE_TYPE_GUID = '426F6F74-0000-11AA-AA11-00306543ECAC'
LOCAL_USER_TYPE_ID = 0x10060002
BOOT_DIR_REGEX = re.compile(r'com.apple.boot.(?P<boot_letter>[A-Z])')

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
        sys.stderr.write("Error reading out of bounds of file, exiting.")
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
        sys.stderr.write(f"[!] Invalid sector size {sector_size} (not 512 or 4096 bytes). Exiting.")
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
    fp.seek(start_pos + 176)
    aes_key = try_read_fp(fp, 0x10)
    return aes_key

def AES_XTS_decrypt(aes_key, tweak, ct):
    decryptor = Cipher(
        algorithms.AES(key=aes_key + b'\x00' * 16),
        modes.XTS(tweak=tweak),
    ).decryptor()
    pt = decryptor.update(ct)
    return pt

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

    file_path = os.path.join(f"{boot_dir}/System/Library/Caches/com.apple.corestorage/EncryptedRoot.plist.wipekey")
    EncryptedRoot_data = recover_file(fs, file_path)

    if not EncryptedRoot_data:
        sys.stderr.write("EncryptedRoot.plist.wipekey not found in image file, exiting.")
        sys.exit(1)

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

def main():

    p = argparse.ArgumentParser()
    p.add_argument('image_file')
    args = p.parse_args()
    image_file = args.image_file

    with open(image_file, 'rb') as fp:
        partition_dict = parse_partition_table(fp)

        core_storage_volumes = get_all_partitions_of_type(partition_dict, HEX_CORE_STORAGE_TYPE_GUID)
        if core_storage_volumes == []:
            sys.stderr.write("[!] No CoreStorage volumes found, exiting.")
            sys.exit(1)
        boot_volumes = get_all_partitions_of_type(partition_dict, HEX_APPLE_BOOT_STORAGE_TYPE_GUID)

        # Unlikely to have more than one boot volume, but loop anyway
        for boot_start_pos in boot_volumes:
            EncryptedRoot_data = get_EncryptedRoot_plist_wipekey(image_file, boot_start_pos)

            for cs_start_pos in core_storage_volumes:
                aes_key = parse_corestorage_header(fp, cs_start_pos)

                tweak = b'\x00' * 16
                pt = AES_XTS_decrypt(aes_key, tweak, EncryptedRoot_data)
                d = load_plist_dict(pt)

                user_index = 0
                for i in range(len(d['CryptoUsers'])):
                    # We want the local user login details i.e. not iCloud
                    if d['CryptoUsers'][i].get('UserType') == LOCAL_USER_TYPE_ID:
                        user_index = i
                        passphrase_hint = d['CryptoUsers'][user_index].get('PassphraseHint')

                        name_info = d['CryptoUsers'][user_index].get('UserNamesData')
                        full_name_info = ''
                        username_info  = ''
                        if len(name_info) == 2:
                            full_name_info, username_info = name_info[0].decode(), name_info[1].decode()

                        full_name_info = format_hash_str(full_name_info)
                        passphrase_hint = format_hash_str(passphrase_hint)

                        # Hash info stored in the PassphraseWrappedKEKStruct in decrypted plist
                        PassphraseWrappedKEKStruct = d['CryptoUsers'][user_index].get('PassphraseWrappedKEKStruct')
                        fvde_hash = construct_fvde_hash(PassphraseWrappedKEKStruct)

                        sys.stdout.write(f"{username_info}:{fvde_hash}:::{full_name_info} {passphrase_hint}::\n")

    return


if __name__ == "__main__":
    main()
