# -*- coding: utf-8 -*-
"""
Created on Fri Sep 30 13:46:06 2022

@author: baris
"""

def decodable_offset(offset):
	if len(offset) < 2 or not offset.isalnum():
		return False
	for chiffre_hexadecimal in offset:
		if chiffre_hexadecimal.isalpha():
			if not(chiffre_hexadecimal.lower() in ["a","b","c","d","e","f"]):
				return False
	return True
	
def decodable_byte(byte):
	if len(byte) != 2 or not byte.isalnum():
		return False
	for chiffre_hexadecimal in byte:
		if chiffre_hexadecimal.isalpha():
			if not(chiffre_hexadecimal.lower() in ["a","b","c","d","e","f"] ):
				return False
	return True


print(decodable_offset("D"))