import Utils


def http_decoder(list_octets):
    """list[octet] -> None
    
    La fonction prend en paramètre une liste d'octets codé en hexadecimal et affiche le contenu du message HTTP.
    """
    print(list_octets)
    hex_string = ''.join(str(x) for x in list_octets)
    
    ascii_string = bytes.fromhex(hex_string).decode('ASCII')
    
    print(ascii_string)
    
    return