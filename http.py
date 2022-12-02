import Utils


def http_decoder(list_octets):
    """list[octet] -> list[octet]
    
    La fonction prend en paramètre une liste d'octets codé en hexadecimal et affiche le contenu du message HTTP.
    """
    
    hex_string = ''.join(str(x) for x in list_octets) # On transforme la liste d'octets en une chaine de caractères
    http_string = "Hypertext Transfer Protocol\n" # La chaine de caractère qui contiendra le message HTTP
    
    last_index = 0 # L'index de chaque début de ligne
    for index in range(0, len(hex_string)):
        temporary_string = ''
        # Condition de fin de ligne (caractère 0D 0A)
        if(hex_string[index] == '0' and hex_string[index+1] == 'd' and hex_string[index+2] == '0' and hex_string[index+3] == 'a'):
            temporary_string = hex_string[last_index:index + 4] 
            http_string = http_string + "\t" + bytes.fromhex(temporary_string).decode('ASCII')
            last_index = index + 4
        # Condition de fin d'entête HTTP
        if(hex_string[index] == '0' and hex_string[index+1] == 'd' and hex_string[index+2] == '0' and hex_string[index+3] == 'a' and hex_string[index+4] == '0' and hex_string[index+5] == 'd' and hex_string[index+6] == '0' and hex_string[index+7] == 'a'):
            print(http_string) # On affiche le message HTTP
            return (list_octets[int((index+8)/2):],http_string[29:49])