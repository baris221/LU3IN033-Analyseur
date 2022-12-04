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
from tkinter.messagebox import showinfo

liste=[0,1]
liste1=[0,1,2]


def save(tkinter_file):
    files = [('All Files', '*.*'), 
             ('Python Files', '*.py'),
             ('Text Document', '*.txt'),
             ('Photos','*.png')]
    file_path = fd.asksaveasfilename(filetypes = files, defaultextension = files)
    #print(str(file_path))


    f=open(file_path,"w")
    f.write(str(tkinter_file))
    f.close()



def selectfile():
    filetypes = (
        ('text files', '*.txt'),
        ('All files', '*Allfile*')
    )

    filename = fd.askopenfilename(
        title='resultat.txt',
        initialdir='/resultat',
        filetypes=filetypes)


            

def flowgraph(liste_octets,t,seq_ack,protocol,suite,http_string,change):
    liste=[0,1]
    liste1=[0,1,2,3]
    textToReturn=""
    background="#76FF7B"
    if(protocol=="HTTP"):
        background="#FF0000"
    fr=tk.Frame(t,bg=background)
    adresses_ip=Ip.getAdressIP(liste_octets)
    if(adresses_ip==17):
        adresses_port=Udp.get_Port(liste_octets)
    else:
        adresses_port=Tcp.get_Port(liste_octets,suite)
    
    if(change):
        adresses_port=(adresses_port[1],adresses_port[0])
        adresses_ip=(adresses_ip[1],adresses_ip[0])

    ip_list=[adresses_ip[0],adresses_ip[1],adresses_port[0],adresses_port[1]]

    for j in liste1:
        fr1=tk.Frame(fr,bg=background)

        for i in liste:
            tm="\t ------------------------------------------------> \t"
            if(change):
                tm="\t <------------------------------------------------ \t"
            if j==0 and i==1:
                tm=ip_list[2] #affichage source port 
            if i==0:
                tm=" "
            if j==len(liste1)-2 and i!=0:
                if protocol=="HTTP":
                    tm=tm+" \n"+http_string
                else:
                    tm=tm+" \n Seq ->"+str(seq_ack[0])+", Ack -> "+str(seq_ack[1])+", Win -> "+str(seq_ack[2])
            if j==len(liste1)-1 and i==1:
                tm=ip_list[3] #affichage destination port
            if j==0 and i==0 :
                tm=ip_list[0] #affichage adresse ip de source
            if j==len(liste1)-1 and i==0:
                tm=ip_list[1] #affichage adresse ip de destination
            if i==1 and j==len(liste1)-3:
                tm=protocol+"\n"
            textToReturn=textToReturn+tm+"\n"
            label_t=tk.Label(fr1,text=tm,bg=background)
            label_t.pack(side="top")
        fr1.pack(side="left")

    fr.pack(side="top",expand=True)
    return textToReturn

def showfleche(t,liste):
 
    t_it=""
    frame=tk.Frame(t,bg="#76FF7B")
    for port in liste:       
        label=tk.Label(frame,text=t_it+port[0]+"------->"+port[1]+"\n",bg="#76FF7B",font=20,compound='right')
        label.pack(side="top")
        t_it=t_it+"\t"
    frame.pack(side="left")


    
def showgraph(li,liste_seq_ack,liste_protocol,liste_suite,http_list,list_change,list_port_init):    
    textToSave=""
    t=tk.Tk()
    t.title("Wireshark Flow Graph")
    t.resizable(width=False,height=False)
    t.config(background="#76FF7B")
    i=0
    for frame in li:
        liste_octets=[]
        for line in frame:
            for byte in line:
                liste_octets.append(byte)
        textToSave=textToSave+flowgraph(liste_octets,t,liste_seq_ack[i],liste_protocol[i],liste_suite[i],http_list[i],list_change[i])
        i=i+1
    showfleche(t,list_port_init)
    entry=tk.Entry(t)
    btn = tk.Button(t, text = 'Save', command = lambda : save(textToSave))
    btn.pack(side = "top", pady = 20)
    btn1=tk.Button(t,text="Ouvre Analyseur",command=selectfile)
    btn1.pack(side = "top", pady = 20)
    t.mainloop()
    
#showgraph("TCP_3.txt")