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
        if paquete.haslayer(ICMP) and paquete[ICMP].type == 8 and paquete.haslayer(Raw):
            payload = paquete[Raw].load
            if len(payload) > 0:
                caracter = chr(payload[0])
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
    # 1. Diccionario ampliado con contexto de laboratorio y palabras comunes
    palabras_clave = [
        " y ", " en ", " de ", " la ", " el ", " que ", " a ", " los ", " por ", " con ",
        "criptografia", "seguridad", "redes", "laboratorio", "ping", "icmp", "paquete",
        "hola", "prueba", "test", "mensaje", "texto", "secreto", "clave",
        "es", "un", "una", "las", "para", "como"
    ]
    
    texto_lower = texto.lower()
    puntuacion = 0
    
    # Evaluar por palabras clave (dando más peso a palabras más largas)
    for palabra in palabras_clave:
        if palabra in texto_lower:
            # Multiplicamos la cantidad de veces que aparece por el largo de la palabra
            puntuacion += texto_lower.count(palabra) * (len(palabra) * 2)

    # 2. Análisis de frecuencia de letras (heurística de respaldo)
    # Letras muy comunes en español suman puntos
    letras_comunes = ['e', 'a', 'o', 's', 'r', 'n', 'i', 'd', 'l', 'c', 't']
    for letra in letras_comunes:
        puntuacion += texto_lower.count(letra) * 1
        
    # Letras raras en español restan puntos
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
        print("No se encontraron paquetes ICMP con datos en la captura.")
        sys.exit(1)

    mejor_desplazamiento = 0
    max_puntuacion = -9999 # Empezamos con un número muy bajo por si hay puntuaciones negativas
    
    # Primera pasada: Encontrar el mejor desplazamiento
    for i in range(26):
        texto_prueba = descifrar_cesar(mensaje_extraido, i)
        puntuacion = evaluar_probabilidad_espanol(texto_prueba)
        if puntuacion > max_puntuacion:
            max_puntuacion = puntuacion
            mejor_desplazamiento = i

    COLOR_VERDE = '\033[92m'
    COLOR_RESET = '\033[0m'

    # Segunda pasada: Imprimir todo y destacar el ganador
    for i in range(26):
        texto_final = descifrar_cesar(mensaje_extraido, i)
        
        if i == mejor_desplazamiento:
            print(f"{COLOR_VERDE}{i:<2} {texto_final}{COLOR_RESET}")
        else:
            print(f"{i:<2} {texto_final}")