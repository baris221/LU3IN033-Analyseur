# -*- coding: utf-8 -*-
"""
Created on Sun Oct 30 22:25:49 2022

@author: baris
"""
import Utils

protocoles_ip = {
	"1" : "ICMP",
	"2" : "IGMP",
	"6" : "TCP",
	"8" : "EGP",
	"9" : "IGP",
	"17" : "UDP",
	"36" : "XTP",
	"46" : "RSVP",
}
def decodage_entete_ip(list_octets):
    """list[int]->void"""
    liste_entete=Utils.obtenir_des_chiffres_voulus(list_octets,14,20)
    liste_entete_2=Utils.list_octet_to_chiffre(liste_entete)
    print("IPV4")
    
    version=liste_entete_2[0]
    print("\t Version : "+version)
    
    ihl=liste_entete_2[1]
    print("\t IHL : "+str(int(ihl,16))+" octets 0x("+ihl+")")
    
    tos=liste_entete_2[2]+""+liste_entete_2[3]
    print("\t Type of Service : "+tos)
    
    total_length=liste_entete_2[4]+""+liste_entete_2[5]+""+liste_entete_2[6]+""+liste_entete_2[7]
    print("\t Total Lenght : "+str(int(total_length,16)))
    
    ident=liste_entete_2[8]+""+liste_entete_2[9]+""+liste_entete_2[10]+liste_entete_2[11]
    print("\t Identification : "+ident)
    
    f_fo=liste_entete_2[12]+""+liste_entete_2[13]+""+liste_entete_2[14]+liste_entete_2[15]
    f_fo=Utils.hexa_to_binaire(f_fo)
    print("\t Flags")
    print("\t \t Reserved bit : "+f_fo[0])
    print("\t \t Don't fragment : "+f_fo[1])
    print("\t \t More Fragment : "+f_fo[2])
    
    f_fo=f_fo[2:15]
    print("\t Fragment offset : "+Utils.binaire_to_hexa(f_fo)+"("+str(int(f_fo,2))+")")
    
    ttl=liste_entete_2[16]+""+liste_entete_2[17]
    print("\t Time To Live : "+str(int(ttl,16)))
    
    protocol=liste_entete_2[18]+""+liste_entete_2[19]
    print("\t Protocol : "+protocoles_ip[str(int(protocol,16))]+"("+str(int(protocol,16))+")")
    
    checksum=liste_entete_2[20]+""+liste_entete_2[21]+""+liste_entete_2[22]+""+liste_entete_2[23]
    print("\t Header Checksum [Unverified] : "+checksum)
    
    adress_source=""
    for i in range(24,31,2):
        adress_source=adress_source+"."+str(int(str(liste_entete_2[i])+str(liste_entete_2[i+1]),16))
    adress_source=adress_source.lstrip(".")
    print("\t Source Address : "+adress_source)
    
    adress_dest=""
    for i in range(32,39,2):
        adress_dest=adress_dest+"."+str(int(str(liste_entete_2[i])+str(liste_entete_2[i+1]),16))
    adress_dest=adress_dest.lstrip(".")
    print("\t Destination Address : "+adress_dest)
    
        
options = {
	"0" : "EOOL",
	"1" : "NOP",
	"7" : "RR",
	"68" : "TS",
    "94" : "Route Alert",
	"131" : "LSR",
	"137" : "SSR"
}   
    

def decodage_options(list_octets):
    """list[int]->int
    Elle renvoie la suite """
    liste_entete=Utils.obtenir_des_chiffres_voulus(list_octets,14,20)
    liste_entete_2=Utils.list_octet_to_chiffre(liste_entete)
    ihl=int(liste_entete_2[1],16)
    if(4*ihl > 20):
        trame=Utils.list_octet_to_chiffre(list_octets)
        reste_trame=trame[68:]
        t1=reste_trame[0]+""+reste_trame[1]
        print("\t Option"+options[t1])
        longeur_val=6
        while(int(t1,16) != 0 and longeur_val>4):
            if(t1 != "00" and t1 != "01"):
                l1=reste_trame[2]+""+reste_trame[3]
                longeur_val=int(l1,16)-2
                print("\t \t Length: "+str(longeur_val+2)+" bytes.")
                valeur=""
                for i in range(4,4+longeur_val*2-1,2):
                    valeur=valeur+""+reste_trame[i]+reste_trame[i+1]
                print("\t \t Value : "+valeur)
                del reste_trame[:4+longeur_val*2]
                
                
            t1=reste_trame[0]+""+reste_trame[1]
            
            
        for ind in(i for i,e in enumerate(trame) if e==reste_trame[0]):
            if(trame[ind:ind+len(reste_trame)]==reste_trame):
                return ind+len(reste_trame)
            
    
    return 68





def getAdressIP(list_octets):
    liste_entete=Utils.obtenir_des_chiffres_voulus(list_octets,14,20)
    liste_entete_2=Utils.list_octet_to_chiffre(liste_entete)
    adress_source=""
    for i in range(24,31,2):
        adress_source=adress_source+"."+str(int(str(liste_entete_2[i])+str(liste_entete_2[i+1]),16))
    adress_source=adress_source.lstrip(".")
    
    adress_dest=""
    for i in range(32,39,2):
        adress_dest=adress_dest+"."+str(int(str(liste_entete_2[i])+str(liste_entete_2[i+1]),16))
    adress_dest=adress_dest.lstrip(".")
    
    return(adress_source,adress_dest)

def getPort(list_octets):
    liste_entete=Utils.obtenir_des_chiffres_voulus(list_octets,14,20)
    liste_entete_2=Utils.list_octet_to_chiffre(liste_entete)
    protocol=liste_entete_2[18]+""+liste_entete_2[19]
    return int(protocol,16)
    