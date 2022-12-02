# -*- coding: utf-8 -*-
"""
Created on Thu Nov 10 18:53:09 2022

@author: baris
"""

import tkinter as tk
import Utils
import Ip
import Udp
import Tcp
import tkinter.filedialog as fd

liste=[0,1]
liste1=[0,1,2]


def save():
    files = [('All Files', '*.*'), 
             ('Python Files', '*.py'),
             ('Text Document', '*.txt'),
             ('Photos','*.png')]
    file = fd.asksaveasfile(filetypes = files, defaultextension = files)

            

def flowgraph(liste_octets,t,seq_ack,protocol,suite,http_string):
    liste=[0,1]
    liste1=[0,1,2,3]
    fr=tk.Frame(t,bg="#76FF7B")
    adresses_ip=Ip.getAdressIP(liste_octets)
    if(adresses_ip==17):
        adresses_port=Udp.get_Port(liste_octets)
    else:
        adresses_port=Tcp.get_Port(liste_octets,suite)

    ip_list=[adresses_ip[0],adresses_ip[1],adresses_port[0],adresses_port[1]]

    for j in liste1:
        fr1=tk.Frame(fr,bg="#76FF7B")

        for i in liste:
            tm="------------------------------------------------"
            if j==0 and i==1:
                tm=ip_list[2] #affichage source port 
            if i==0:
                tm=" "
            if j==len(liste1)-2 and i!=0:
                if protocol=="HTTP":
                    tm=tm+"\n"+http_string+"\n"
                else:
                    tm=tm+"> \n Seq ->"+str(seq_ack[0])+", Ack -> "+str(seq_ack[1])+", Win -> "+str(seq_ack[2])
            if j==len(liste1)-1 and i==1:
                tm=ip_list[3] #affichage destination port
            if j==0 and i==0 :
                tm=ip_list[0] #affichage adresse ip de source
            if j==len(liste1)-1 and i==0:
                tm=ip_list[1] #affichage adresse ip de destination
            if i==1 and j==len(liste1)-3:
                tm=protocol+"\n"
            label_t=tk.Label(fr1,text=tm,bg="#76FF7B")
            label_t.pack(side="top")
        fr1.pack(side="left")

    fr.pack(side="top",expand=True)
    
def showgraph(path_to_file,liste_seq_ack,liste_protocol,liste_suite,http_list):    

    li=Utils.lire_trace(path_to_file)
    t=tk.Tk()
    t.title("Wireshark Flow Graph")
    t.config(background="#76FF7B")
    i=0
    for frame in li:
        liste_octets=[]
        for line in frame:
            for byte in line:
                liste_octets.append(byte)
        flowgraph(liste_octets,t,liste_seq_ack[i],liste_protocol[i],liste_suite[i],http_list[i])
        i=i+1

    btn = tk.Button(t, text = 'Save', command = lambda : save())
    btn.pack(side = "top", pady = 20)
    t.mainloop()
    
#showgraph("TCP_3.txt")