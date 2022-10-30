# -*- coding: utf-8 -*-
"""
Created on Sun Oct 30 22:20:04 2022

@author: baris
"""

import Utils

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
    liste_entete=Utils.obtenir_des_chiffres_voulus(list_octets,0,14)
    liste_entete_2=Utils.list_octet_to_chiffre(liste_entete)
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