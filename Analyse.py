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
    nb_bits=len(suite_chiffres_h)*4
    suite_chiffres_2=int(suite_chiffres_h,16)
    suite_chiffres_b=bin(suite_chiffres_2)
    suiteARetourner=suite_chiffres_b[2:].zfill(nb_bits)
    return suiteARetourner

def binaire_to_hexa(suite_chiffres_b):
    suite_chiffre_2=int(suite_chiffres_b,2)
    suite_chiffres_h=hex(suite_chiffre_2)
    return suite_chiffres_h

def obtenir_des_chiffres_voulus(suite_chiffres_h,debut,nb): #utilisable aussi pour les binaires
    fin=debut+nb
    list_voulu=[]
    for i in range(debut,fin):
        list_voulu.append(suite_chiffres_h[i])
    
    return list_voulu

def list_octet_to_chiffre(liste_octet):
    liste_chiffre=[]
    for octet in liste_octet:
        liste_chiffre.append(octet[0])
        liste_chiffre.append(octet[1])
    return liste_chiffre  

ethernet = {
	"0800" : "IP Datagram",
	"0805" : "X.25 level 3",
	"0806" : "ARP",
	"8035" : "RARP",
	"8098" : "AppleTalk",
    "8137" : "IPX"
}      

def decodage_entete_ethernet(list_octets):
    liste_entete=obtenir_des_chiffres_voulus(list_octets,0,14)
    liste_entete_2=list_octet_to_chiffre(liste_entete)
    print(" Ethernet 2")
    adress_dest=""
    adress_source=""
    for i in range(0,11,2):
        adress_dest=adress_dest+":"+liste_entete_2[i]+liste_entete_2[i+1]
    adress_dest=adress_dest.lstrip(":")
    print("\t Adresse de destionation : "+adress_dest)
    
    for i in range(12,23,2):
        adress_source=adress_source +":"+liste_entete_2[i]+liste_entete_2[i+1]
    adress_source=adress_source.lstrip(":")
    print("\t Adresse de la source : "+adress_source)
    
    type_ethernet=liste_entete_2[24]+liste_entete_2[25]+liste_entete_2[26]+liste_entete_2[27]
    print("\t Type "+ethernet[type_ethernet]+"(0x"+type_ethernet+")")
        

#print(hexa_to_binaire("AB456"))

def main():
    nom_fic=input("Veuillez rédiger le nom du fichier :")
    li=lire_trace(nom_fic)
    for frame in li:
        liste_octets=[]
        for line in frame:
            for byte in line:
                liste_octets.append(byte)
        decodage_entete_ethernet(liste_octets)

main()