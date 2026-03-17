from scapy.all import IP, ICMP, sr1
import time
import sys

def enviar_ping_sigiloso(texto_cifrado):
    ip_destino = "8.8.8.8"  # IP de los DNS de Google
    print(f"Iniciando envío sigiloso hacia {ip_destino}...")
    
    # ID estático para la "sesión" de ping, similar a lo que hace el OS
    id_ping = 12345 

    for i, caracter in enumerate(texto_cifrado):
        # 1. Obtenemos el byte del caracter a enviar
        byte_caracter = caracter.encode('utf-8')
        
        # 2. Generamos 55 bytes de relleno (padding) para llegar a los 56 bytes típicos de macOS/Linux.
        # Usamos una secuencia simple de bytes que cambia ligeramente para parecer ruido normal.
        padding = bytes([(x + i) % 256 for x in range(55)])
        
        # El payload final es nuestro caracter oculto al principio + 55 bytes de relleno normal
        payload = byte_caracter + padding
        
        # 3. Construimos el paquete: 
        # type=8 (Echo Request), le pasamos el ID de sesión y un número de secuencia que incrementa
        paquete = IP(dst=ip_destino) / ICMP(type=8, id=id_ping, seq=i+1) / payload
        
        # Enviamos el paquete y esperamos respuesta (verbose=0 evita que Scapy ensucie la terminal)
        respuesta = sr1(paquete, timeout=2, verbose=0)
        
        if respuesta:
            print(f"[{i+1}/{len(texto_cifrado)}] Sent 1 packet (Carácter oculto enviado). Respuesta recibida.")
        else:
            print(f"[{i+1}/{len(texto_cifrado)}] Tiempo de espera agotado.")
            
        # 4. Esperamos exactamente 1 segundo, simulando el comando ping nativo
        time.sleep(1)
        
    print("\nTransmisión finalizada.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Uso: sudo venv/bin/python pingv4.py "texto a enviar"')
        sys.exit(1)
        
    texto = sys.argv[1]
    enviar_ping_sigiloso(texto)