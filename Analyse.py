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


def lire_trace(path_to_file):
	with open(path_to_file, "rt") as f:
		frame_list = []
		line_list = f.read().splitlines()
		if int(line_list[0].split()[0], 16) != 0:
			print("Error: Malformed frame: Frame doesn't start with offset 0")
			return
		i = -1
		for j in range(len(line_list)):
			line_list[j] = line_list[j].split()
			if decodable_offset(line_list[j][0]):
				if int(line_list[j][0], 16) == 0:
					i = i+1
					frame_list.append([])
			frame_list[i].append(line_list[j])
			
		for frame in frame_list:
			for line in frame:
				if not decodable_offset(line[0]):
					frame.remove(line)
					
		#v2
		for frame in frame_list:
			last_offset = -1
			for idx, line in enumerate(frame):
				if idx != len(frame)-1:
					#print(str(int(line[0], 16)) + ">" + str(last_offset))
					if int(line[0], 16) > last_offset:
						next_offset = frame[(idx + 1) % len(frame)][0]
						#print(next_offset)
						last_offset = int(line[0], 16)
						if int(next_offset, 16) > 0:
							if ((len(line) - 1) == int(next_offset, 16) - int(line[0], 16)):
								line.pop(0)
							elif ((len(line) - 1) < int(next_offset, 16) - int(line[0], 16)):
								print("Error: Malformed frame: Line incomplete")
								quit()
							elif ((len(line) - 1) > int(next_offset, 16) - int(line[0], 16)):
								nb_bytes =  int(next_offset, 16) - int(line[0], 16)
								line.pop(0)
								del line [nb_bytes:]
				else:
					line.pop(0)
					for i in range(len(line)):
						if not decodable_byte(line[i]):
							del line[i:]
							break
							
				#print(line)
								
							
		
		
		#print(frame_list)
		return frame_list