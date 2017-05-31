# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay (at) synacktiv.com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#!/usr/bin/python

# -*- coding: utf-8 -*-

# by Fist0urs

class ARC4Cipher(object):
     def __init__(self, key):
         self.key = key

     def encrypt(self, data):
         S = range(256)
         j = 0
         out = []
         for i in range(256):
             j = (j + S[i] + ord( self.key[i % len(self.key)] )) % 256
             S[i] , S[j] = S[j] , S[i]
         i = j = 0
         for char in data:
             i = ( i + 1 ) % 256
             j = ( j + S[i] ) % 256
             S[i] , S[j] = S[j] , S[i]
             out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
         return ''.join(out)

     def decrypt(self, data):
         return self.encrypt(data)

def new(key):
    return ARC4Cipher(key)
