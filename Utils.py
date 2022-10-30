# -*- coding: utf-8 -*-
"""
Created on Sun Oct 30 22:21:11 2022

@author: baris
"""

def decodable_offset(offset):
    """string->boolean
    Si l'offset est décodable, la fonction renvoie true"""
    if len(offset) < 2 or not offset.isalnum():
        return False
    for chiffre_hexadecimal in offset:
        if chiffre_hexadecimal.isalpha():
            if not(chiffre_hexadecimal.lower() in ["a","b","c","d","e","f"]):
                return False
    return True
	
def decodable_byte(byte):
    """byte->boolean
    Si lr byte est décodable, la fonction retourne true"""
    if len(byte) != 2 or not byte.isalnum():
        return False
    for chiffre_hexadecimal in byte:
        if chiffre_hexadecimal.isalpha():
            if not(chiffre_hexadecimal.lower() in ["a","b","c","d","e","f"] ):
                return False
    return True


def lire_trace(path_to_file):
    """FILE->list[byte]
    Elle renvoie la liste des bytes au fichier path_to_file"""
    with open(path_to_file, "rt") as f:
        frame_list = []
        #line_list contient les contenus de la liste
        line_list = f.read().splitlines()
        #L'offset doit commencer par 0
        if int(line_list[0].split()[0], 16) != 0:
            print("Error: Malformed frame: Frame doesn't start with offset 0")
            return
        i = -1
        #Frame list va contenir des lignes qui commencent par des binaires decodables
        #Si ça commence par zéro,on le met en avant sinon à la fin
        for j in range(len(line_list)):
            line_list[j] = line_list[j].split()
            if(line_list[j]==[]):
                continue
            if decodable_offset(line_list[j][0]):
                if int(line_list[j][0], 16) == 0:
                    i = i+1
                    frame_list.append([])
            frame_list[i].append(line_list[j])

        #On enléve si le binaire non décodable de frame			
        for frame in frame_list:
            for line in frame:
                if not decodable_offset(line[0]):
                    frame.remove(line)
					
		#v2
        for frame in frame_list:
            last_offset = -1
            #On prend l'identifiant de chaque élement de frame
            for idx, line in enumerate(frame):
                if idx != len(frame)-1:
					#print(str(int(line[0], 16)) + ">" + str(last_offset))
                    #Si la valeur de l'octet est plus grand que -1
                    if int(line[0], 16) > last_offset:
                        next_offset = frame[(idx + 1) % len(frame)][0]
						#print(next_offset)
                        #Revalorisation de last_offset
                        last_offset = int(line[0], 16)
                        #Si la valeur de offset prochain est différent de 0.
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
																
                #dernier octet
                else:
                    line.pop(0)
                    for i in range(len(line)):
                        if not decodable_byte(line[i]):
                            del line[i:]
                            break
							
				#print(line)
								
							
        #print(frame_list)
        return frame_list

def hexa_to_binaire(suite_chiffres_h):
    """hexadecimal number->binary number
    La fonction retourne la valeur binaire de nombre héxadécimal"""
    nb_bits=len(suite_chiffres_h)*4
    suite_chiffres_2=int(suite_chiffres_h,16)
    suite_chiffres_b=bin(suite_chiffres_2)
    suiteARetourner=suite_chiffres_b[2:].zfill(nb_bits)
    return suiteARetourner

def binaire_to_hexa(suite_chiffres_b):
    """list[binary number]->list[hexadecimal number]
    La fonction retourne la valuer héxadécimal de nombre binaire"""
    suite_chiffre_2=int(suite_chiffres_b,2)
    suite_chiffres_h=hex(suite_chiffre_2)
    return suite_chiffres_h

def obtenir_des_chiffres_voulus(suite_chiffres_h,debut,nb): #utilisable aussi pour les binaires
    """list[]->list[]
    Renvoie la liste qui contient des éléments de début à debut+nb"""
    fin=debut+nb
    list_voulu=[]
    for i in range(debut,fin):
        list_voulu.append(suite_chiffres_h[i])
    
    return list_voulu

def list_octet_to_chiffre(liste_octet):
    """list[(int,int)]->list[int]
    Renvoie la liste qui place tous les couples en ordre"""
    liste_chiffre=[]
    for octet in liste_octet:
        liste_chiffre.append(octet[0])
        liste_chiffre.append(octet[1])
    return liste_chiffre