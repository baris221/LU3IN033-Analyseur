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
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)
    
    print("TCP (Transmission control protocol)")
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    print("\tSource port: " + str(int(src_port, 16)))
	
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    print("\tDestination port: " + str(int(dest_port, 16)))
    
    print("\tSequence number :"+str(seq))
    seq_number=liste_entete_2[8] + "" + liste_entete_2[9] + "" + liste_entete_2[10] + "" + liste_entete_2[11]+""+liste_entete_2[12] + "" + liste_entete_2[13] + "" + liste_entete_2[14] + "" + liste_entete_2[15]
    print("\tSequence Number (raw) :"+str(int(seq_number,16)))
    
    print("\tAcknowledgement number :"+str(awk))
    ack_number=liste_entete_2[16] + "" + liste_entete_2[17] + "" + liste_entete_2[18] + "" + liste_entete_2[19]+""+liste_entete_2[20] + "" + liste_entete_2[21] + "" + liste_entete_2[22] + "" + liste_entete_2[23]
    print("\tAcknowledgement Number (raw) :"+str(int(ack_number,16)))
    
    header_length=liste_entete_2[24]
    print("\tHeader Length :"+str(int(header_length,16)))
    
    f_fo=liste_entete_2[25]+""+liste_entete_2[26]+""+liste_entete_2[27]
    print("\tFlags :"+f_fo)
    f_fo=Utils.hexa_to_binaire(f_fo)
    print("\t\tReserved "+f_fo[0]+f_fo[1]+f_fo[2])
    print("\t\tNonce :"+f_fo[3])
    print("\t\tCongestion Window Reduced (CWR) :"+f_fo[4])
    print("\t\tECN-Echo :"+f_fo[5])
    print("\t\tUrgent :"+f_fo[6])
    print("\t\tAcknowledgement :"+f_fo[7])
    print("\t\tPush :"+f_fo[8])
    print("\t\tReset :"+f_fo[9])
    print("\t\tSyn :"+f_fo[10])
    print("\t\tFin :"+f_fo[11])
    
    window=liste_entete_2[28] + "" + liste_entete_2[29] + "" + liste_entete_2[30] + "" + liste_entete_2[31]
    print("\tWindow :"+str(int(window,16)))
    
    check_sum=liste_entete_2[32] + "" + liste_entete_2[33] + "" + liste_entete_2[34] + "" + liste_entete_2[35]
    print("\tChecksum : 0x("+check_sum+")")
    
    urgent_pointer=liste_entete_2[36] + "" + liste_entete_2[37] + "" + liste_entete_2[38] + "" + liste_entete_2[39]
    print("\tUrgent pointer :"+str(int(urgent_pointer,16)))
    
    return int(window,16)
    
    
def get_Port(liste_octets,suite):
    
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)
    
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    src_port= str(int(src_port, 16))
	
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    dest_port=str(int(dest_port, 16))   
    
    return(src_port,dest_port)


def Tcp_options(suite,liste_octets):
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)

    header_length=int(liste_entete_2[24],16)
    
    if(4*header_length>20):
        print("\tOptions:")
        trame=Utils.list_octet_to_chiffre(liste_octets)
        reste_trame=trame[108:]
        t1=reste_trame[0]+""+reste_trame[1]
        longeur_val=1
        if t1!="00" and t1!="01":
            longeur_val=int((reste_trame[2]+""+reste_trame[3]),16)
            print(longeur_val)
        reste_trame=reste_trame[2*longeur_val:]
        print("\t\tOption :"+options[t1])
        while(reste_trame!= [] and t1!="00"):
            t1=reste_trame[0]+""+reste_trame[1]
            if t1 in options.keys():
                print("\t\tOption :"+options[t1])
            if t1!="01":
                longeur_val=int((reste_trame[2]+""+reste_trame[3]),16)
            else:
                longeur_val=1
            reste_trame=reste_trame[2*longeur_val:]

        return 108+((4*header_length)-20)*2
    else:
        print("\tNo option")
        return 108

    