import Utils


def http_decoder(list_octets):
    """list[octet] -> None
    
    La fonction prend en paramètre une liste d'octets codé en hexadecimal et affiche le contenu du message HTTP.
    """
    print("Hypertext Transfer Protocol")
    
    hex_string = ''.join(str(x) for x in list_octets) # On transforme la liste d'octets en une chaine de caractères
    ascii_string = '' # La chaine de caractère qui contiendra le message HTTP
    
    #ascii_string = bytes.fromhex(hex_string).decode('ASCII')
    last_index = 0
    for index in range(0, len(hex_string)):
        temporary_string = ''
        if(hex_string[index] == '0' and hex_string[index+1] == 'd' and hex_string[index+2] == '0' and hex_string[index+3] == 'a'):
            temporary_string = hex_string[last_index:index + 4]
            ascii_string = ascii_string + "\t" + bytes.fromhex(temporary_string).decode('ASCII')
            last_index = index + 4
    
    print(ascii_string)
    
    return