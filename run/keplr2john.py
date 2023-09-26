#!/usr/bin/env python3

#######################################################################################
# Keplr wallet data extractor
#######################################################################################
#
# Keplr is an open-source browser extension non-custodial wallet for 
# the Cosmos Inter blockchain ecosystem.
#
# website:      https://www.keplr.app/
#
#
# Keplr development details:
#       https://github.com/chainapsis/keplr-wallet
#
# Keplr is a React/Typescript project that uses the Chrome extension 
# settings to save data. This is done in a LevelDB format.
#######################################################################################
#
# This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
# is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
#######################################################################################

import sys, os.path, json
from ccl_chrome_indexeddb import ccl_leveldb

# Welcome message
prog = os.path.basename(sys.argv[0])
print('Keplr wallet data extractor\n')

#######################################################################################
# Check program params
#######################################################################################
if len(sys.argv) < 2 or len(sys.argv) > 3 or sys.argv[1].startswith("-"):
    print('Error: Too few or too much parameters')
    print(f"usage: {prog} <Keplr_wallet_folder> <password>", file=sys.stderr)
    print(f"       where <password> is optional\n", file=sys.stderr)
    
    print('You can find the <Keplr_wallet_folder> where Google Chrome may save the extension settings:')
    print(' - On Windows you can check the following folders:')
    print('     * %AppData%\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap')
    print('     * %AppData%\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage')
    print('     * %AppData%\\Local\\Google\\Chrome\\User Data\\Default\\IndexedDB\\chrome-extension_dmkamcknogkgcdfhhbddcghachkejeap_0.indexeddb.leveldb')
    
    # TODO: Check on Linux
    # TODO: Support Firefox
    # print(' - On Linux you can check the following folders:')
    # print('     * ~/.google-chrome/Default/Local Extension Settings/dmkamcknogkgcdfhhbddcghachkejeap')
    print('')
    sys.exit(0)

#######################################################################################
# Load database
#######################################################################################
try:
    wallet_folder = sys.argv[1]
    leveldb_records = ccl_leveldb.RawLevelDb(wallet_folder)
except Exception as e:
    print(f'Error loading database: {e}')
    sys.exit(0)

#######################################################################################
# Search all records and load users
#######################################################################################
users = set()
for record in leveldb_records.iterate_records_raw():
    # Check keyring store
    if b"keyring/key-store" == record.user_key or b"keyring/key-multi-store" == record.user_key:
        
        kv_db_key = record.user_key.decode('utf-8', 'ignore')
        key_store = json.loads(record.value.decode('utf-8', 'ignore'))
        if key_store is None:
            continue
        
        #######################################################################################
        # Example of output:
        #######################################################################################
        #   print(f"{kv_db_key} : {key_store}\n")
        #
        # keyring/key-store :
        # {
        #     'bip44HDPath': {'account': 0, 'addressIndex': 0, 'change': 0}, 
        #     'coinTypeForChain': {'cosmoshub': 118}, 
        #     'crypto':
        #     {
        #         'cipher': 'aes-128-ctr', 
        #         'cipherparams': {'iv': '4d9b46c8a573704780c9770e92a48316'}, 
        #         'ciphertext': '8a3b159e9fd7e104049aca4f432575b5bb95c7e3f6829e1549ca9066ed4fcf0a6ff4eb355923a28a4171af171bc36055a2631f10f35dd0b8a5872a51ca9c2c09e7f4e407ec614d546717e1a03c', 
        #         'kdf': 'scrypt', 
        #         'kdfparams': {'dklen': 32, 'n': 131072, 'p': 1, 'r': 8, 'salt': '31aa4c50f62b54b4e4bf0a1f6ff38ef8bcc3902ab309533037e96ff60ecfd4a6'}, 
        #         'mac': '8ed6786d2ea66ac9a2f8347b8c84ff7eb250c0d5a9aae616500f24e635a7ada7'
        #     }, 
        #     'meta': {'__id__': '1', 'name': 'john_doe'}, 
        #     'type': 'mnemonic', 
        #     'version': '1.2'
        # }
        def check_hex(s: str) -> bool:
            try:
                int(s, 16)
                return True
            except:
                return False
            
        def load_user_hash(key_store):
            # General checks
            if 'crypto' not in key_store:
                print("Error: No crypto found")
                return
            if 'version' not in key_store or key_store['version'] != '1.2':
                print(f"Warning: Version {key_store['version']} different from 1.2")
            
            if 'cipher' not in key_store['crypto']:
                print("Warning: No cipher found")
            elif key_store['crypto']['cipher'] != 'aes-128-ctr':
                print(f"Warning: cipher '{key_store['crypto']['cipher']}' different from 'aes-128-ctr'")
                
            if 'kdf' not in key_store['crypto']:
                print("Warning: No kdf found")
            elif key_store['crypto']['kdf'] != 'scrypt':
                print(f"Error: kdf '{key_store['crypto']['kdf']}' different from 'scrypt'")
                return
            
            if 'kdfparams' not in key_store['crypto']:
                print("Warning: No kdfparams found")
            else:
                if 'dklen' in key_store['crypto']['kdfparams'] and key_store['crypto']['kdfparams']['dklen'] != 32:
                    print(f"Error: kdfparams:dklen '{key_store['crypto']['kdfparams']['dklen']}' different from 32")
                    return
                if 'n' in key_store['crypto']['kdfparams'] and key_store['crypto']['kdfparams']['n'] != 131072:
                    print(f"Error: kdfparams:n '{key_store['crypto']['kdfparams']['n']}' different from 131072")
                    return
                if 'p' in key_store['crypto']['kdfparams'] and key_store['crypto']['kdfparams']['p'] != 1:
                    print(f"Error: kdfparams:p '{key_store['crypto']['kdfparams']['p']}' different from 1")
                    return
                if 'r' in key_store['crypto']['kdfparams'] and key_store['crypto']['kdfparams']['r'] != 8:
                    print(f"Error: kdfparams:r '{key_store['crypto']['kdfparams']['r']}' different from 8")
                    return
            
            # Username
            if 'meta' not in key_store or 'name' not in key_store['meta']:
                print("Error: No username found")
                return
            username = key_store['meta']['name']
            
            # Ciphertext
            if 'ciphertext' not in key_store['crypto']:
                print("Error: No ciphertext found")
                return
            ciphertext_hex = key_store['crypto']['ciphertext']
            if not check_hex(ciphertext_hex):
                print("Error: Ciphertext not in hexadecimal format")
                return
            
            # Salt
            if 'kdfparams' not in key_store['crypto'] or 'salt' not in key_store['crypto']['kdfparams']:
                print("Error: No salt found")
                return
            salt_hex = key_store['crypto']['kdfparams']['salt']
            if not check_hex(salt_hex):
                print("Error: Salt not in hexadecimal format")
                return
            if len(salt_hex) != 64:
                print(f"Error: Salt size is {len(salt_hex)//2} and should be 32")
                return
            
            # Mac
            if 'mac' not in key_store['crypto']:
                print("Error: No mac found")
                return
            mac_hex = key_store['crypto']['mac']
            if not check_hex(mac_hex):
                print("Error: MAC not in hexadecimal format")
                return
            if len(mac_hex) != 64:
                print(f"Error: Salt size is {len(mac_hex)//2} and should be 32")
                return
            
            # IV
            iv = ''
            if 'cipherparams' in key_store['crypto'] and 'iv' in key_store['crypto']['cipherparams']:
                iv = key_store['crypto']['cipherparams']['iv']
            
            users.add((username, salt_hex, ciphertext_hex, mac_hex, iv))
            
        # Add the user to the set of users
        if kv_db_key == "keyring/key-store":
            load_user_hash(key_store)
            
        if kv_db_key == "keyring/key-multi-store":
            for store in key_store:
                load_user_hash(store)    
 
#######################################################################################
# Show users
#######################################################################################
print('#################################################################################')
print('Users found on the database in the format -> username:$keplr$salt*ciphertext*mac')
print('#################################################################################')
for user in users:
    print(f'{user[0]}:$keplr${user[1]}*{user[2]}*{user[3]}')       
        
#######################################################################################################
# Crypto -> Try to test a password and decrypt possibly the seed
#
# https://github.com/chainapsis/keplr-wallet/blob/master/packages/background/src/keyring/crypto.ts#L45
#######################################################################################################
if len(sys.argv) < 3:
    sys.exit(0)
    
password_str = sys.argv[2]
print('')
print('#################################################################################')
print(f'Simple test of password: {password_str}')
print('Result in the format -> username:<Match>|<NotMatch>:decrypted_data')
print('                        where decrypted_data can be the mnemonic seed')
print('#################################################################################')
try:
    import hashlib, scrypt
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    for user in users:
        _, salt_hex, ciphertext_hex, mac_hex, iv_hex  = user
        
        # Hash
        derived_key = scrypt.hash(password=password_str.encode('utf_8'), salt=bytes.fromhex(salt_hex), N=131072, r=8, p=1, buflen=32)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        calculated_mac = hashlib.sha256(derived_key[16:] + ciphertext_bytes).hexdigest()
        
        # Try to decrypt data
        iv = bytes.fromhex(iv_hex)
        ctr = Counter.new(nbits=8*len(iv), initial_value=int.from_bytes(iv, 'big'), little_endian=False)
        decrypt_cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)
        plain_text = decrypt_cipher.decrypt(ciphertext_bytes)
        
        # Show results
        print(f'{user[0]}:{"<Match>" if calculated_mac == mac_hex else "<NotMatch>"}:{plain_text}')
        
except Exception as e:
    print(f'Error testing supplied password: {e}')
    sys.exit(0)
