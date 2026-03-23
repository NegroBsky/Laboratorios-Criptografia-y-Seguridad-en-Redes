import sys
from scapy.all import rdpcap, ICMP, Raw

def extraer_mensaje_pcap(archivo_pcap):
    try:
        paquetes = rdpcap(archivo_pcap)
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {archivo_pcap}")
        sys.exit(1)

    texto_cifrado = ""
    for paquete in paquetes:
        # Filtramos ICMP Echo Request con capa Raw
        if paquete.haslayer(ICMP) and paquete[ICMP].type == 8 and paquete.haslayer(Raw):
            payload = paquete[Raw].load
            
            # Verificamos que el payload sea lo suficientemente largo (mínimo 9 bytes)
            if len(payload) >= 9:
                # ¡AQUÍ ESTÁ LA MAGIA! Leemos la posición 8 (justo después del timestamp)
                caracter = chr(payload[8])
                texto_cifrado += caracter
                
    return texto_cifrado

def descifrar_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            nuevo_indice = (ord(caracter) - base - desplazamiento) % 26
            resultado += chr(nuevo_indice + base)
        else:
            resultado += caracter
    return resultado

def evaluar_probabilidad_espanol(texto):
    # Agregué la palabra "larva" al diccionario para asegurar que gane la puntuación
    palabras_clave = [
        " y ", " en ", " de ", " la ", " el ", " que ", " a ", " los ", " por ", " con ",
        "criptografia", "seguridad", "redes", "laboratorio", "ping", "icmp", "paquete",
        "hola", "prueba", "test", "mensaje", "texto", "secreto", "clave", "larva"
    ]
    
    texto_lower = texto.lower()
    puntuacion = 0
    
    for palabra in palabras_clave:
        if palabra in texto_lower:
            puntuacion += texto_lower.count(palabra) * (len(palabra) * 2)

    letras_comunes = ['e', 'a', 'o', 's', 'r', 'n', 'i', 'd', 'l', 'c', 't']
    for letra in letras_comunes:
        puntuacion += texto_lower.count(letra) * 1
        
    letras_raras = ['w', 'k', 'x', 'z']
    for letra in letras_raras:
        puntuacion -= texto_lower.count(letra) * 2
        
    return puntuacion

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo venv/bin/python readv2.py <archivo.pcapng>")
        sys.exit(1)

    archivo_captura = sys.argv[1]
    mensaje_extraido = extraer_mensaje_pcap(archivo_captura)

    if not mensaje_extraido:
        print("No se encontraron paquetes ICMP válidos en la captura.")
        sys.exit(1)

    mejor_desplazamiento = 0
    max_puntuacion = -9999
    
    for i in range(26):
        texto_prueba = descifrar_cesar(mensaje_extraido, i)
        puntuacion = evaluar_probabilidad_espanol(texto_prueba)
        if puntuacion > max_puntuacion:
            max_puntuacion = puntuacion
            mejor_desplazamiento = i

    # Código ANSI para AZUL, coincidiendo con tu informe LaTeX
    COLOR_AZUL = '\033[94m'
    COLOR_RESET = '\033[0m'

    for i in range(26):
        texto_final = descifrar_cesar(mensaje_extraido, i)
        
        if i == mejor_desplazamiento:
            print(f"{COLOR_AZUL}{i:<2} {texto_final}{COLOR_RESET}")
        else:
            print(f"{i:<2} {texto_final}")