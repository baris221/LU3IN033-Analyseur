# -*- coding: utf-8 -*-
"""
Created on Fri Sep 30 13:46:06 2022

@author: baris
"""
import contextlib
import sys
import Ethernet
import Utils
import Ip
    


#print(hexa_to_binaire("AB456"))

def main():
    nom_fic=sys.argv[1]
    li=Utils.lire_trace(nom_fic)
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
                Ethernet.decodage_entete_ethernet(liste_octets)
                Ip.decodage_entete_ip(liste_octets)
                suite=Ip.decodage_options(liste_octets)
                print("-------------------------------------")
                i=i+1

main()
