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
import Http
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
    port_ex=("","")
    liste_seq_ack=[]
    liste_protocol=[]
    liste_suite=[]
    with open("resultat.txt","w") as f:
        with contextlib.redirect_stdout(f):
            for frame in li:
                liste_octets=[]
                for line in frame:
                    for byte in line:
                        liste_octets.append(byte)
                longeur_list=len(liste_octets)
                # Mes modifications
                print("Coucou ici la gueule de liste octets:")
                print(liste_octets[0:20])
                # Fin de mes modifications"""
                print("Frame "+str(i)+": "+str(longeur_list)+" bytes "+"("+str(longeur_list*8)+" bits).")
                print("\n")
                Ethernet.decodage_entete_ethernet(liste_octets)
                print("\n")
                Ip.decodage_entete_ip(liste_octets)
                transportation=Ip.getPort(liste_octets)
                suite=Ip.decodage_options(liste_octets)
                liste_suite.append(suite)
                print("\n")
                if(suite!=68):
                    continue
                #udp
                if(transportation==17):
                    udp_values=Udp.decodage_entete_udp(liste_octets,suite)
                    seq=1
                    ack=1
                    liste_protocol.append("UDP")
                    print("\n")
                #tcp
                if(transportation==6):
                    adresse_port=Tcp.get_Port(liste_octets,suite)
                    if(port_ex[0]==adresse_port[1] and port_ex[1]==adresse_port[0] ):
                        seq,ack=ack,seq
                    window=Tcp.decodage_TCP_entete(liste_octets,suite,seq,ack)
                    suite=Tcp.Tcp_options(suite,liste_octets)
                    liste_seq_ack.append((seq,ack,window))                   
                    seq=seq+int(longeur_list-suite/2)               
                    port_ex=adresse_port
                    liste_protocol.append("TCP")
                
                    print("\n")
                    if(adresse_port[0]=="80" or adresse_port[1]=="80") and suite<len(liste_octets):
                        print("HTTP")
                        liste_protocol.append("HTTP")
                if(liste_protocol[-1]=="HTTP"):
                    Http.http_decoder(liste_octets[suite:])
                
                print("-------------------------------------")
                i=i+1
    flowgraph.showgraph(nom_fic,liste_seq_ack,liste_protocol,liste_suite)
    print(suite)



main()
    
