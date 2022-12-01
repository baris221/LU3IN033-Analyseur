# -*- coding: utf-8 -*-
"""
Created on Wed Nov  9 17:29:30 2022

@author: baris
"""
import Utils



def decodage_entete_udp(liste_octets,suite):
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,16)
    
    print("User Datagram Protocol (UDP)")
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    print("\tSource port: " + str(int(src_port, 16)))
	
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    print("\tDestination port: " + str(int(dest_port, 16)))
	
    length = liste_entete_2[8] + "" + liste_entete_2[9] + "" + liste_entete_2[10] + "" + liste_entete_2[11]
    print("\tLength: " + str(int(length, 16)))
	
    checksum = liste_entete_2[12] + "" + liste_entete_2[13] + "" + liste_entete_2[14] + "" + liste_entete_2[15]
    print("\tChecksum: 0x" + checksum)
    return (int(length, 16)-8, int(src_port, 16))


def get_Port(liste_octets):
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,68,16)
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    src_port=str(int(src_port,16))
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    dest_port=str(int(dest_port,16))
    
    return(src_port,dest_port)


