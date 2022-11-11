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

liste=[0,1]
liste1=[0,1,2]
t=tk.Tk()

t.title("Wireshark Flow Graph")
t.config(background="#76FF7B")

nom_fic="deux-trames-correctes.trame"
li=Utils.lire_trace(nom_fic)
for frame in li:
    fr=tk.Frame(t,bg="#76FF7B")
    liste_octets=[]
    for line in frame:
        for byte in line:
            liste_octets.append(byte)
            
    adresses_ip=Ip.getAdressIP(liste_octets)
    adresses_port=Udp.get_Port(liste_octets)

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
            if j==0 and i==0:
                tm=ip_list[0]
            if j==len(liste1)-1 and i==0:
                tm=ip_list[1]
            label_t=tk.Label(fr1,text=tm,bg="#76FF7B")
            label_t.pack(side="top")
        fr1.pack(side="left")

    fr.pack(side="top",expand=True)
t.mainloop()
