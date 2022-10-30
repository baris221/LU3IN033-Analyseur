# -*- coding: utf-8 -*-
"""
Created on Fri Sep 30 13:46:06 2022

@author: baris
"""
import contextlib

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

ethernet = {
	"0800" : "IP Datagram",
	"0805" : "X.25 level 3",
	"0806" : "ARP",
	"8035" : "RARP",
	"8098" : "AppleTalk",
    "8137" : "IPX"
}

def decodage_entete_ethernet(list_octets):
    """list[int]->void
    Elle prend 28 premiers bits et décode les bits en fonction de
    12 premiers bits destinations,12 bits suivant source,4 bits type de ethernet"""
    liste_entete=obtenir_des_chiffres_voulus(list_octets,0,14)
    liste_entete_2=list_octet_to_chiffre(liste_entete)
    print("Ethernet 2")
    adress_dest=""
    adress_source=""
    for i in range(0,11,2):
        adress_dest=adress_dest+":"+liste_entete_2[i]+liste_entete_2[i+1]
    adress_dest=adress_dest.lstrip(":")
    print("\t Adresse de destination : "+adress_dest)
    
    for i in range(12,23,2):
        adress_source=adress_source +":"+liste_entete_2[i]+liste_entete_2[i+1]
    adress_source=adress_source.lstrip(":")
    print("\t Adresse de la source : "+adress_source)
    
    type_ethernet=liste_entete_2[24]+liste_entete_2[25]+liste_entete_2[26]+liste_entete_2[27]
    print("\t Type "+ethernet[type_ethernet]+"(0x"+type_ethernet+")")
    
protocoles_ip = {
	"1" : "ICMP",
	"2" : "IGMP",
	"6" : "TCP",
	"8" : "EGP",
	"9" : "IGP",
	"17" : "UDP",
	"36" : "XTP",
	"46" : "RSVP"
}
def decodage_entete_ip(list_octets):
    """list[int]->void"""
    liste_entete=obtenir_des_chiffres_voulus(list_octets,14,20)
    liste_entete_2=list_octet_to_chiffre(liste_entete)
    print("IPV4")
    
    version=liste_entete_2[0]
    print("\t Version : "+version)
    
    ihl=liste_entete_2[1]
    print("\t IHL : "+str(int(ihl,16))+"octets 0x("+ihl+")")
    
    tos=liste_entete_2[2]+""+liste_entete_2[3]
    print("\t Type of Service : "+tos)
    
    total_length=liste_entete_2[4]+""+liste_entete_2[5]+""+liste_entete_2[6]+""+liste_entete_2[7]
    print("\t Total Lenght : "+str(int(total_length,16)))
    
    ident=liste_entete_2[8]+""+liste_entete_2[9]+""+liste_entete_2[10]+liste_entete_2[11]
    print("\t Identification : "+ident)
    
    f_fo=liste_entete_2[12]+""+liste_entete_2[13]+""+liste_entete_2[14]+liste_entete_2[15]
    f_fo=hexa_to_binaire(f_fo)
    print("\t Flags")
    print("\t \t Reserved bit : "+f_fo[0])
    print("\t \t Don't fragment : "+f_fo[1])
    print("\t \t More Fragment : "+f_fo[2])
    
    f_fo=f_fo[2:15]
    print("\t Fragment offset : "+binaire_to_hexa(f_fo)+"("+str(int(f_fo,2))+")")
    
    ttl=liste_entete_2[16]+""+liste_entete_2[17]
    print("\t Time To Live : "+str(int(ttl,16)))
    
    protocol=liste_entete_2[18]+""+liste_entete_2[19]
    print("\t Protocol : "+protocoles_ip[str(int(protocol,16))]+"("+str(int(protocol,16))+")")
    
    checksum=liste_entete_2[20]+""+liste_entete_2[21]+""+liste_entete_2[22]+""+liste_entete_2[23]
    print("\t Header Checksum unverified : "+checksum)
    
    adress_source=""
    for i in range(24,31,2):
        adress_source=adress_source+"."+str(int(str(liste_entete_2[i])+str(liste_entete_2[i+1]),16))
    adress_source=adress_source.lstrip(".")
    print("\t Source Adress : "+adress_source)
    
    adress_dest=""
    for i in range(32,39,2):
        adress_dest=adress_dest+"."+str(int(str(liste_entete_2[i])+str(liste_entete_2[i+1]),16))
    adress_dest=adress_dest.lstrip(".")
    print("\t Destination Adress : "+adress_dest)
        
    
    

def decodage_options(list_octets):
    """list[int]->int
    Elle renvoie la suite """
    liste_entete=obtenir_des_chiffres_voulus(list_octets,14,20)
    liste_entete_2=list_octet_to_chiffre(liste_entete)
    ihl=int(liste_entete_2[1],16)
    if(4*ihl !=20):
        print("Option")
    
    return 68
    

#print(hexa_to_binaire("AB456"))

def main():
    nom_fic=input("Veuillez rédiger le nom du fichier :")
    li=lire_trace(nom_fic)
    i=1
    with open("resultat.txt","w") as f:
        with contextlib.redirect_stdout(f):
            for frame in li:
                liste_octets=[]
                for line in frame:
                    for byte in line:
                        liste_octets.append(byte)
                longeur_list=len(liste_octets)
                print("Frame "+str(i)+": "+str(longeur_list)+" bytes "+"("+str(longeur_list*8)+" bits).")
                decodage_entete_ethernet(liste_octets)
                decodage_entete_ip(liste_octets)
                print("-------------------------------------")
                i=i+1

main()
