# -*- coding: utf-8 -*-
"""
Created on Sat Nov 12 17:09:48 2022

@author: baris
"""
import Utils

def decodage_TCP_entete(liste_octets,suite,seq,awk):
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)
    
    print("TCP (Transmission control protocol)")
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    print("\t Source port: " + str(int(src_port, 16)))
	
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    print("\t Destination port: " + str(int(dest_port, 16)))
    
    print("\t Sequence number :"+str(seq))
    seq_number=liste_entete_2[8] + "" + liste_entete_2[9] + "" + liste_entete_2[10] + "" + liste_entete_2[11]+""+liste_entete_2[12] + "" + liste_entete_2[13] + "" + liste_entete_2[14] + "" + liste_entete_2[15]
    print("\t Sequence Number (raw) :"+str(int(seq_number,16)))
    
    print("\t Acknowledgement number :"+str(awk))
    ack_number=liste_entete_2[16] + "" + liste_entete_2[17] + "" + liste_entete_2[18] + "" + liste_entete_2[19]+""+liste_entete_2[20] + "" + liste_entete_2[21] + "" + liste_entete_2[22] + "" + liste_entete_2[23]
    print("\t Acknowledgement Number (raw) :"+str(int(ack_number,16)))
    
    header_length=liste_entete_2[24]
    print("\t Header Length :"+str(int(header_length,16)))
    
    f_fo=liste_entete_2[25]+""+liste_entete_2[26]+""+liste_entete_2[27]
    print("\t Flags :"+f_fo)
    f_fo=Utils.hexa_to_binaire(f_fo)
    print("\t \t Reserved "+f_fo[0]+f_fo[1]+f_fo[2])
    print("\t \t Nonce :"+f_fo[3])
    print("\t \t Congestion Window Reduced (CWR) :"+f_fo[4])
    print("\t \t ECN-Echo :"+f_fo[5])
    print("\t \t Urgent :"+f_fo[6])
    print("\t \t Acknowledgement :"+f_fo[7])
    print("\t \t Push :"+f_fo[8])
    print("\t \t Reset :"+f_fo[9])
    print("\t \t Syn :"+f_fo[10])
    print("\t \t Fin :"+f_fo[11])
    
    window=liste_entete_2[28] + "" + liste_entete_2[29] + "" + liste_entete_2[30] + "" + liste_entete_2[31]
    print("\t Window :"+str(int(window,16)))
    
    check_sum=liste_entete_2[32] + "" + liste_entete_2[33] + "" + liste_entete_2[34] + "" + liste_entete_2[35]
    print("\t Checksum : 0x("+check_sum+")")
    
    urgent_pointer=liste_entete_2[36] + "" + liste_entete_2[37] + "" + liste_entete_2[38] + "" + liste_entete_2[39]
    print("\t Urgent pointer :"+str(int(urgent_pointer,16)))
    
    return int(window,16)
    
    
def get_Port(liste_octets):
    
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,68,40)
    
    src_port = liste_entete_2[0] + "" + liste_entete_2[1] + "" + liste_entete_2[2] + "" + liste_entete_2[3]
    src_port= str(int(src_port, 16))
	
    dest_port = liste_entete_2[4] + "" + liste_entete_2[5] + "" + liste_entete_2[6] + "" + liste_entete_2[7]
    dest_port=str(int(dest_port, 16))   
    
    return(src_port,dest_port)

options={"00":"EOOL",
"01":"No-operation",
"02":"Maximum Segment Size",
"03":"WSOPT",
"04":"SACK permitted",
"05":"SACK Selective"}

def Tcp_options(suite,liste_octets):
    liste_entete=Utils.list_octet_to_chiffre(liste_octets)
    liste_entete_2= Utils.obtenir_des_chiffres_voulus(liste_entete,suite,40)

    header_length=int(liste_entete_2[24],16)
    
    if(4*header_length>20):
        print("\t Options:")
        trame=Utils.list_octet_to_chiffre(liste_octets)
        reste_trame=trame[108:]
        print(reste_trame)
        #reste_trame=reste_trame[:(header_length-20)*2-1]
        t1=reste_trame[0]+""+reste_trame[1]
        reste_trame=reste_trame[2:]
        print("\t \t Option :"+options[t1])
        while(reste_trame!= []):
            t1=reste_trame[0]+""+reste_trame[1]
            if t1 in options.keys():
                print("\t \t Option :"+options[t1])

            reste_trame=reste_trame[2:]

        return 108+((4*header_length)-20)*2

    
    else:
        print("\t No option")
        return 108

    