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
import Udp
import Tcp
    


#print(hexa_to_binaire("AB456"))

def main():
    if(len(sys.argv)!=2):
        print("Error")
        return
    nom_fic=sys.argv[1]
    li=Utils.lire_trace(nom_fic)
    i=1
    seq=1
    ack=1
    ex_longeur=0
    with open("resultat.txt","w") as f:
        with contextlib.redirect_stdout(f):
            for frame in li:
                liste_octets=[]
                for line in frame:
                    for byte in line:
                        liste_octets.append(byte)
                longeur_list=len(liste_octets)
                print("Frame "+str(i)+": "+str(longeur_list)+" bytes "+"("+str(longeur_list*8)+" bits).")
                print("\n")
                Ethernet.decodage_entete_ethernet(liste_octets)
                print("\n")
                transportation=Ip.decodage_entete_ip(liste_octets)
                suite=Ip.decodage_options(liste_octets)
                print("\n")
                if(suite!=68):
                    continue
                if(transportation==17):
                    udp_values=Udp.decodage_entete_udp(liste_octets,suite)
                if(transportation==6):
                    Tcp.decodage_TCP_entete(liste_octets,suite,seq,ack)
                
                if not(longeur_list==54 and longeur_list==56):
                    seq=seq+longeur_list-54
                else:
                    ack=ack+longeur_list-54
                
                if(not(ex_longeur==0)and ((ex_longeur>56 and longeur_list<=56)or(ex_longeur<=56 and longeur_list>56))):
                    seq,ack=ack,seq
                
                print("\n")
                
                print("-------------------------------------")
                i=i+1
                ex_longeur=longeur_list



main()
    
