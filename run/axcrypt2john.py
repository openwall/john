#!/usr/bin/python

# AxCrypt 1.x encrypted file parser for JtR
# 2016 by Fist0urs <eddy.maaalou at gmail.com>.

# This software is Copyright (c) 2016, Fist0urs <eddy.maaalou at gmail.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without modification,
# are permitted.

import sys, struct

# file is beginning with 16bytes constant header
GUID='\xc0\xb9\x07\x2e\x4f\x93\xf1\x46\xa0\x15\x79\x2c\xa1\xd9\xe8\x21'
OFFSET_TYPE=4
SIZE_KEYDATA=24  # size of constant in keywrap (0xA6*8) + size of DEK (16)
SIZE_SALT=16
SIZE_ITERATION=4

StructKeys=[]

def usage():
	print >> sys.stderr, 'usage: %s <axxfile> [KEY-FILE]\n' % sys.argv[0]
	print >> sys.stderr, 'Script to extract hash from AxCrypt encrypted file or self-decrypting binary\n'
	print >> sys.stderr, 'optional arguments:\n  KEY-FILE			 path to optional key-file provided'
	sys.exit(1)

def DWORD_to_int(string_dword):
	string_dword_reversed = string_dword[::-1]
	return int('0x'+str(string_dword_reversed.encode('hex')), 16)

def parse_PE(axxdata):
	i = 0
	while(axxdata[i:i+16] != GUID):
		i += 1
	return axxdata[i:]

def parse_axxfile(axxfile):
	stream=open(axxfile, 'rb')
	axxdata=stream.read()
	stream.close()

	# if header is 'MZ'
	if axxdata[:2] == '\x4D\x5a':
		offset_PE_magic = struct.unpack('<L', axxdata[60:64])[0]
		# if 'PE' assume PE
		if axxdata[offset_PE_magic:offset_PE_magic+2] == '\x50\x45':
			axxdata = parse_PE(axxdata)

	sizeof_file=len(axxdata)

	if (axxdata[:16] != GUID):
		print "Be Careful, GUID is different from axcrypt's one..." 

	header_datalen_offset = 16
	headertype = '\x02' # first type encountered

	# headertype of dataencrypted section is 0x3f
	while(headertype != 63):
		header_datalen = ord(axxdata[header_datalen_offset])
		headertype = ord(axxdata[header_datalen_offset + OFFSET_TYPE])
		
		# probably a StructKey
		if (header_datalen == 49 and headertype == 04):
			offset_to_keydata = header_datalen_offset + OFFSET_TYPE + 1
			offset_to_salt = offset_to_keydata + SIZE_KEYDATA
			offset_to_iteration = offset_to_salt + SIZE_SALT
			
			dword_str = axxdata[offset_to_iteration:offset_to_iteration + SIZE_ITERATION]
			
			StructKeys.append({'KeyData' : axxdata[offset_to_keydata:offset_to_salt]
						, 'Salt' : axxdata[offset_to_salt:offset_to_iteration]
						,'Iteration' : DWORD_to_int(dword_str)})

		header_datalen_offset += header_datalen
		
		if (header_datalen_offset >= sizeof_file):
			print "Could not parse file, exiting"
			sys.exit(0)
	return StructKeys[0]['KeyData'],StructKeys[0]['Salt'],StructKeys[0]['Iteration']

if __name__=="__main__":
	if (len(sys.argv) != 2 and len(sys.argv) != 3):
		usage()
	
	# A_DEK == wrappedKey
	wrappedKey, Salt, nb_iteration = parse_axxfile(sys.argv[1])

	version = 1
	
	keyfile_content = ''
	key_file_name = ''
	# dummy strip to relative path
	axxfile = sys.argv[1][sys.argv[1].rfind("/")+1:]

	if (len(sys.argv) == 3):
		keyfile = open(sys.argv[2], 'r')
		keyfile_content = '*' + keyfile.read().encode("hex")
		key_file_name = '*' + sys.argv[2][sys.argv[2].rfind("/")+1:]
		keyfile.close()

	print axxfile + key_file_name + ":$axcrypt$" + "*" + str(version) + "*" + str(nb_iteration) + "*" + Salt.encode("hex") + "*" + wrappedKey.encode("hex") + keyfile_content
