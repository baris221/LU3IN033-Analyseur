# -*- coding: utf-8 -*-
"""
Created on Sat Nov 12 17:09:48 2022

@author: baris
"""
import Utils

options={"00":"EOOL",
"01":"No-operation",
"02":"Maximum Segment Size",
"03":"WSOPT",
"04":"SACK permitted",
"05":"SACK Selective",
"08":"Timestamps"}

def decodage_TCP_entete(liste_octets,suite,seq,awk):
    """list[octets],int,int,int -> void
    Elle contient en argument des nombres relatives de sequence et acqitement
    aorès de suite"""
    #On prend de suite(la fin de ip) jusqu'à 40+suite
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)
    
    tcp_string="Transmission Control Protocol\n"
    seq_aug=0
    #Affichage de port source
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    tcp_string += "\tSource port: " + str(int(src_port, 16))+"\n"
	
    #Affichage de port destination
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    tcp_string += "\tDestination port: " + str(int(dest_port, 16))+"\n"
    
    #Nombre de sequence et sequence relatif
    tcp_string += "\tSequence number :"+str(seq)+"\n"
    seq_number=liste_entete_2[8] + "" + liste_entete_2[9] + "" + liste_entete_2[10] + "" + liste_entete_2[11]+""+liste_entete_2[12] + "" + liste_entete_2[13] + "" + liste_entete_2[14] + "" + liste_entete_2[15]
    tcp_string += "\tSequence Number (raw) :"+str(int(seq_number,16))+"\n"
    
    #Nombre d'acquitement et acquitement relatif
    tcp_string += "\tAcknowledgement number :"+str(awk)+"\n"
    ack_number=liste_entete_2[16] + "" + liste_entete_2[17] + "" + liste_entete_2[18] + "" + liste_entete_2[19]+""+liste_entete_2[20] + "" + liste_entete_2[21] + "" + liste_entete_2[22] + "" + liste_entete_2[23]
    tcp_string += "\tAcknowledgement Number (raw) :"+str(int(ack_number,16))+"\n"
    
    #Affichage de headerlength
    header_length=liste_entete_2[24]
    tcp_string += "\tHeader Length :"+str(int(header_length,16))+"\n"
    
    #Affichage des flags
    f_fo=liste_entete_2[25]+""+liste_entete_2[26]+""+liste_entete_2[27]
    tcp_string += "\tFlags :"+f_fo+"\n"
    f_fo=Utils.hexa_to_binaire(f_fo)
    tcp_string += "\t\tReserved "+f_fo[0]+f_fo[1]+f_fo[2]+"\n"
    tcp_string += "\t\tNonce :"+f_fo[3]+"\n"
    tcp_string += "\t\tCongestion Window Reduced (CWR) :"+f_fo[4]+"\n"
    tcp_string += "\t\tECN-Echo :"+f_fo[5]+"\n"
    tcp_string += "\t\tUrgent :"+f_fo[6]+"\n"
    tcp_string += "\t\tAcknowledgement :"+f_fo[7]+"\n"
    tcp_string += "\t\tPush :"+f_fo[8]+"\n"
    tcp_string += "\t\tReset :"+f_fo[9]+"\n"
    tcp_string += "\t\tSyn :"+f_fo[10]+"\n"
    tcp_string += "\t\tFin :"+f_fo[11]+"\n"
    if(f_fo[10]=="1" or f_fo[11]=="1"):
        seq_aug=1
    
    #Window
    window=liste_entete_2[28] + "" + liste_entete_2[29] + "" + liste_entete_2[30] + "" + liste_entete_2[31]
    tcp_string += "\tWindow :"+str(int(window,16))+"\n"
    
    #Checksum
    check_sum=liste_entete_2[32] + "" + liste_entete_2[33] + "" + liste_entete_2[34] + "" + liste_entete_2[35]
    tcp_string += "\tChecksum : 0x("+check_sum+")\n"
    
    #Urgent pointer
    urgent_pointer=liste_entete_2[36] + "" + liste_entete_2[37] + "" + liste_entete_2[38] + "" + liste_entete_2[39]
    tcp_string += "\tUrgent pointer :"+str(int(urgent_pointer,16))+"\n"
    print(tcp_string)
    
    return (int(window,16),seq_aug,0)
    
    
def get_Port(liste_octets,suite):
    """list[octets],int->(str,str)
    Elle renvoie la port source et destination"""
    
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)
    
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    src_port= str(int(src_port, 16))
	
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    dest_port=str(int(dest_port, 16))   
    
    return(src_port,dest_port)


def Tcp_options(suite,liste_octets):
    """list[octets],int->void
    Elle affiche des options de TCP"""
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)

    header_length=int(liste_entete_2[24],16)
    
    #Si header vaut, ça veut dire pas de l'option
    if(4*header_length>20):
        print("\tOptions:")
        trame=Utils.list_octet_to_chiffre(liste_octets)
        reste_trame=trame[suite+40:]
        t1=reste_trame[0]+""+reste_trame[1]
        #Si le type de l'option n'est pas 00 ou 01,on doit calculer la longeur
        longeur_val=1
        if t1!="00" and t1!="01":
            longeur_val=int((reste_trame[2]+""+reste_trame[3]),16)
            print(longeur_val)
        #Multiple par deux car ce sont des bits
        reste_trame=reste_trame[2*longeur_val:]
        print("\t\tOption :"+options[t1])
        #application du même algo
        while(reste_trame!= [] and t1!="00"):
            t1=reste_trame[0]+""+reste_trame[1]
            if t1 in options.keys():
                print("\t\tOption :"+options[t1])
            if t1!="01":
                longeur_val=int((reste_trame[2]+""+reste_trame[3]),16)
            else:
                longeur_val=1
            reste_trame=reste_trame[2*longeur_val:]

        #Ajout suite+40+longeur des options
        return suite+40+((4*header_length)-20)*2
    else:
        index=suite+40
        if(len(liste_entete)==index):
            return index
        while(liste_entete[index]=="0" and liste_entete[index+1]=="0"):
            index=index+2
            print(index)
            if(len(liste_entete)==index):
                break
        #Si pas de l'option,ajoute directement 40
        print("\tNo options")
        return index

    