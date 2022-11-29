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
import flowgraph
    


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
    adresse_ip_ex=("","")
    liste_seq_ack=[]
    liste_protocol=[]
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
                Ip.decodage_entete_ip(liste_octets)
                transportation=Ip.getPort(liste_octets)
                suite=Ip.decodage_options(liste_octets)
                print("\n")
                if(suite!=68):
                    continue
                #udp
                if(transportation==17):
                    udp_values=Udp.decodage_entete_udp(liste_octets,suite)
                    seq=1
                    ack=1
                    liste_protocol.append("UDP")
                #tcp
                if(transportation==6):
                    adresse_ip=Ip.getAdressIP(liste_octets)
                    if(adresse_ip_ex[0]==adresse_ip[1] and adresse_ip_ex[1]==adresse_ip[0] ):
                        seq,ack=ack,seq
                    window=Tcp.decodage_TCP_entete(liste_octets,suite,seq,ack)
                    suite=Tcp.Tcp_options(suite,liste_octets)
                    liste_seq_ack.append((seq,ack,window))                   
                    seq=seq+int(longeur_list-suite/2)               
                    adresse_ip_ex=adresse_ip
                    liste_protocol.append("TCP")
                
                print("\n")
                
                print("-------------------------------------")
                i=i+1
    flowgraph.showgraph(nom_fic,liste_seq_ack,liste_protocol)
    print(suite)



main()
    
