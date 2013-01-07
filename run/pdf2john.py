#!/usr/bin/env python

# Written in 2013 by Shane Quigley, < shane at softwareontheside.info >

import re
import sys

class PdfParser:
	def __init__(self,file_name):
		self.file_name = file_name
		f = open(file_name, 'r')
		self.encrypted = f.read()
		f.close()
		psr = re.compile('PDF-\d\.\d')
		self.pdf_spec = psr.findall(self.encrypted)[0]

	def parse(self):
		trailer = self.get_trailer()
		object_id = self.get_encrypted_object_id(trailer)
		encryption_dictionary = self.get_encryption_dictionary(object_id)
		dr = re.compile('\d+')
		vr = re.compile('\/V \d')
		rr = re.compile('\/R \d')
		v = dr.findall(vr.findall(encryption_dictionary)[0])[0]
		r = dr.findall(rr.findall(encryption_dictionary)[0])[0]
		lr = re.compile('\/Length \d+')
		longest = 0
		length = ''
		for le in lr.findall(encryption_dictionary):
			if(int(dr.findall(le)[0]) > longest):
				longest = int(dr.findall(le)[0])
				length = dr.findall(le)[0]
		pr = re.compile('\/P -\d+')
		p = pr.findall(encryption_dictionary)[0]
		pr = re.compile('-\d+')
		p = pr.findall(p)[0]
		meta = self.is_meta_data_encrypted(encryption_dictionary)
		idr = re.compile('\/ID\s*\[\s*<\w+>\s*<\w+>\s*\]')
		i_d = idr.findall(trailer)[0] #id key word
		idr = re.compile('<\w+>')
		i_d = idr.findall(trailer)[0]
		i_d = i_d.replace('<','')
		i_d = i_d.replace('>','')
		i_d = i_d.lower()
		passwords = self.get_passwords_for_JtR(encryption_dictionary)
		output = self.file_name+':$pdf$'+v+'*'+r+'*'+length+'*'+p+'*'+meta+'*'
		output += str(len(i_d)/2)+'*'+i_d+'*'+passwords
		print output

	def get_passwords_for_JtR(self, encryption_dictionary):
		output = ""
		letters = ["U","O"]
		if("1.7" in self.pdf_spec):
			letters = ["U","O","UE","OE"]
		for let in letters:
			pr_str = '\/'+let+'\([^)]+\)'
			pr = re.compile(pr_str)
			pas = pr.findall(encryption_dictionary)
			if(len(pas) > 0):
				pas = pr.findall(encryption_dictionary)[0]
				#Because regexs in python suck
				while(pas[-2] == '\\'):
					pr_str += '[^)]+\)'
					pr = re.compile(pr_str)
					pas = pr.findall(encryption_dictionary)[0]
				output +=  self.get_password_from_byte_string(pas)+"*"
			else:
				pr = re.compile(let+'\s*<\w+>')
				pas = pr.findall(encryption_dictionary)[0]
				pr = re.compile('<\w+>')
				pas = pr.findall(pas)[0]
				pas = pas.replace("<","")
				pas = pas.replace(">","")
				output += str(len(pas)/2)+'*'+pas.lower()+'*'
		return output[:-1]

	def is_meta_data_encrypted(self, encryption_dictionary):
		mr = re.compile('\/EncryptMetadata\s\w+')
		if(len(mr.findall(encryption_dictionary)) > 0):
			wr = re.compile('\w+')
			is_encrypted = wr.findall(mr.findall(encryption_dictionary)[0])[-1]
			if(is_encrypted == "false"):
				return "0"
			else:
				return "1"
		else:
			return "1"

	def get_encryption_dictionary(self,object_id):
		encryption_dictionary = self.get_data_between(object_id+" obj", "endobj")
		for o in encryption_dictionary.split("endobj"):
			if(object_id+" obj" in o):
				encryption_dictionary = o
		return encryption_dictionary

	def get_encrypted_object_id(self,trailer):
		oir = re.compile('\/Encrypt\s\d+\s\d\sR')
		object_id = oir.findall(trailer)[0]
		oir = re.compile('\d+ \d')
		object_id = oir.findall(object_id)[0]
		return object_id

	def get_trailer(self):
		trailer = self.get_data_between("trailer", ">>")
		if(trailer == ""):
			trailer = self.get_data_between("DecodeParms", "stream")
			if(trailer == ""):
				raise "Can't find trailer"
		if(trailer != "" and trailer.find("Encrypt") == -1):
			raise "File not encrypted"
		return trailer

	def get_data_between(self,s1, s2):
		output = ""
		inside_first = False
		lines = self.encrypted.split('\n')
		for line in lines:
			inside_first = inside_first or line.find(s1) != -1
			if(inside_first):
				output += line
				if(line.find(s2) != -1):
					break
		return output

	def get_password_from_byte_string(self, o_or_u):
		pas = ""
		escape_seq = False
		escapes = 0
		excluded_indexes = [0,1,2]
		#For UE & OE in 1.7 spec
		if(o_or_u[2] != '('):
			excluded_indexes.append(3)
		for i in range(len(o_or_u)):
			if(i not in excluded_indexes):
				if(len(hex(ord(o_or_u[i])).replace('0x', '')) == 1 and o_or_u[i] != "\\"[0]):
					pas += "0"#need to be 2 digit hex numbers
				if(o_or_u[i] != "\\"[0] or escape_seq):
					if(escape_seq):
						esc = "\\"+o_or_u[i]
						esc = self.unescape(esc)
						if(len(hex(ord(esc[0])).replace('0x', '')) == 1):
							pas += "0"
						pas += hex(ord(esc[0])).replace('0x', '')
						escape_seq = False
					else:
						pas += hex(ord(o_or_u[i])).replace('0x', '')
				else:
					escape_seq = True
					escapes += 1
		output = len(o_or_u)-(len(excluded_indexes)+1)-escapes
		return str(output)+'*'+pas[:-2]

	def unescape(self,esc):
		escape_seq_map = {'\\n':"\n", '\\s':"\s", '\\e':"\e", '\\r':"\r", '\\t':"\t", '\\v':"\v", '\\f':"\f", '\\b':"\b", '\\a':"\a", '\\e':"\e", "\\)":")", "\\(":"(", "\\\\":"\\" }
		return escape_seq_map[esc]


c = 0
for arg in sys.argv:
	if(c != 0):
		parser = PdfParser(arg)
		parser.parse()
	c+=1
