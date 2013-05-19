#!/usr/bin/python

# reverseXOR.py
# Written by John Pierce
# May 5, 2013
#
# Writes out bytecodes XORED with 0x10 in a format suitable for processing
# and pushing onto the stack in doubleword increments
#

import sys

input = sys.argv[1]



print 'String length : ' +str(len(input)-1)

reverse  = input[::-1]
print reverse

encoded1 = ""
encoded2 = ""

for x in bytearray(reverse[1:]) :
	#XOR encoding
	y = x^0x10
	encoded1 += '\\x'
	encoded1 += '%02x' % y
	encoded2 += '0x'
	encoded2 += '%02x,' % y
print '\n XOR 1: ' + encoded1
print '\n XOR 2: ' + encoded2
