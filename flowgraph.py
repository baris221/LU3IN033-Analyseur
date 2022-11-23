# -*- coding: utf-8 -*-
"""
Created on Thu Nov 10 18:53:09 2022

@author: baris
"""

import tkinter as tk
import Utils
import Ip
import sys
import Udp
import Tcp

liste=[0,1]
liste1=[0,1,2]




            

def flowgraph(liste_octets,t):
    liste=[0,1]
    liste1=[0,1,2]
    fr=tk.Frame(t,bg="#76FF7B")
    adresses_ip=Ip.getAdressIP(liste_octets)
    if(adresses_ip==17):
        adresses_port=Udp.get_Port(liste_octets)
    else:
        adresses_port=Tcp.get_Port(liste_octets)

    ip_list=[adresses_ip[0],adresses_ip[1],adresses_port[0],adresses_port[1]]

    for j in liste1:
        fr1=tk.Frame(fr,bg="#76FF7B")

        for i in liste:
            tm="------------------------------------------------"
            if j==0:
                tm=ip_list[2]
            if i==0:
                tm=" "
            if j==len(liste1)-2 and i!=0:
                tm=tm+">"
            if j==len(liste1)-1:
                tm=ip_list[3]
            if j==0 and i==0 and not(j==len(liste1)-1):
                tm=ip_list[0]
            if j==len(liste1)-1 and i==0:
                tm=ip_list[1]
            label_t=tk.Label(fr1,text=tm,bg="#76FF7B")
            label_t.pack(side="top")
        fr1.pack(side="left")

    fr.pack(side="top",expand=True)
    
def showgraph(path_to_file):    

    li=Utils.lire_trace(path_to_file)
    t=tk.Tk()
    t.title("Wireshark Flow Graph")
    t.config(background="#76FF7B")
    for frame in li:
        liste_octets=[]
        for line in frame:
            for byte in line:
                liste_octets.append(byte)
        flowgraph(liste_octets,t)

    t.mainloop()
    
showgraph("TCP_3.txt")