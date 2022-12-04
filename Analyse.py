# -*- coding: utf-8 -*-
"""
Created on Fri Sep 30 13:46:06 2022

@author: baris
"""
import contextlib
import sys
import os
import Ethernet
import Utils
import Ip
import Udp
import Tcp
import http
import flowgraph
    


#print(hexa_to_binaire("AB456"))

def main():
    if(len(sys.argv)!=2):
        print("Error")
        return
    nom_fic=sys.argv[1]
    li=Utils.lire_trace(nom_fic)
    i=1
    seq=0
    ack=0
    m=1
    port_ex=("","")
    liste_seq_ack=[] #une liste contenant des valeurs sequence et acquittement
    liste_protocol=[] #une liste de protocol qui contient soit http ou tcp
    liste_suite=[] #une liste qui contient les numéros suite pour les messages
    liste_change=[] #une liste qui nous donne si les ports sont inversés par rapport àport initial
    proto="" #le protocole du trame
    http_list=[] #liste contenant des messages http sinon vide 
    port_init=[] #le port de l'état initial, change dans les cas des noveaux messages
    list_port_init=[]
    liste_info_pertinents=[]
    with open("resultat/resultat.txt","w") as f:
        with contextlib.redirect_stdout(f):
            for frame in li:
                liste_octets=[]
                for line in frame:
                    for byte in line:
                        liste_octets.append(byte)
                infopertinent=""
                longeur_list=len(liste_octets)
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
                # Ici on gère le cas où on a un datagramme UDP
                if(transportation==17):
                    udp_values=Udp.decodage_entete_udp(liste_octets,suite)
                    seq=1
                    ack=1
                    liste_protocol.append("UDP")
                    print("\n")
                # Ici on gère le cas où on a un segment TCP
                if(transportation==6):
                    adresse_port=Tcp.get_Port(liste_octets,suite)
                    if(adresse_port != port_ex and port_ex[0]!=adresse_port[1] and port_ex[1]!=adresse_port[0] ):
                        seq=0
                        ack=0
                        m=1
                    
                    if(port_ex[0]==adresse_port[1] and port_ex[1]==adresse_port[0] ): 
                        seq,ack=ack,seq
                    if(m==1):
                        port_init=adresse_port
                        list_port_init.append(port_init)
                    cng=(port_init[0]==adresse_port[1] and port_init[1]==adresse_port[0] and i!=1)
                    liste_change.append(cng)
                    (window,seq_aug,awk_aug)=Tcp.decodage_TCP_entete(liste_octets,suite,seq,ack)
                    infopertinent=Tcp.getInfoPertinent(suite,liste_octets)
                    suite=Tcp.Tcp_options(suite,liste_octets)
                    liste_info_pertinents.append(infopertinent)
                    #print(suite)
                    liste_seq_ack.append((seq,ack,window))                   
                    seq=seq+int(longeur_list-suite/2)+seq_aug               
                    port_ex=adresse_port
                    proto="TCP"
                
                    print("\n")
                    if(adresse_port[0]=="80" or adresse_port[1]=="80") and suite<len(liste_octets):
                        proto="HTTP"
                data = []
                liste_protocol.append(proto)
                # Ici on gère les cas où on a un message HTTP
                http_string=""
                if(liste_protocol[-1]=="HTTP"):
                    (data,http_string) = http.http_decoder(liste_octets[int(suite/2):])
                http_list.append(http_string) 
                # Si le dernier protocole encapsule des données, on affiche leur taille
                #print(data)
                if(len(data) != 0):
                    print("data: "+str(len(data))+" bytes")
                
                print("-------------------------------------")
                i=i+1
                m=m+1
    flowgraph.showgraph(li,liste_seq_ack,liste_protocol,liste_suite,http_list,liste_change,liste_info_pertinents,list_port_init)
    #print(suite)
    #print(liste_change)



if not os.path.exists("resultat"):
    os.mkdir("resultat")
main()
    
