# -*- coding: utf-8 -*-
"""
Created on Fri Sep 30 13:46:06 2022

@author: baris
"""

def decodable_offset(offset):
	if len(offset) < 2 or not offset.isalnum():
		return False
	for chiffre_hex in offset:
		if chiffre_hex.isalpha():
			if not(chiffre_hex.lower() >= "a" and chiffre_hex.lower() <= "f"):
				return False
	return True
	
def decodable_byte(byte):
	if len(byte) != 2 or not byte.isalnum():
		return False
	for chiffre_hex in byte:
		if chiffre_hex.isalpha():
			if not(chiffre_hex.lower() >= "a" and chiffre_hex.lower() <= "f"):
				return False
	return True
