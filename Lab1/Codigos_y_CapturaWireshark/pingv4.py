import sys
import time
import struct
from scapy.all import IP, ICMP, sr1, Raw

def enviar_ping_sigiloso(texto_cifrado):
    ip_destino = "8.8.8.8"
    print(f"Iniciando inyección sigilosa hacia {ip_destino}...")
    
    # Mantenemos un ID estático para simular la misma sesión de ping
    id_ping = 12345 

    for i, caracter in enumerate(texto_cifrado):
        # 1. MANTENER TIMESTAMP (Primeros 8 bytes): 
        # Los sistemas operativos envían el tiempo en dos bloques de 4 bytes: segundos y microsegundos.
        # Esto engaña a Wireshark para que lo decodifique como una fecha válida.
        tiempo_actual = time.time()
        tv_sec = int(tiempo_actual)
        tv_usec = int((tiempo_actual - tv_sec) * 1000000)
        # Empaquetamos en formato Little-Endian (<), dos enteros sin signo de 4 bytes (I I)
        timestamp_bytes = struct.pack("<II", tv_sec, tv_usec) 
        
        # 2. INYECTAR CARÁCTER: Lo colocamos exactamente en la posición 8 (el 9no byte)
        byte_caracter = caracter.encode('utf-8')
        
        # 3. RELLENO MEDIO (Bytes 9 al 15): Completamos la secuencia hasta llegar a 0x10
        relleno_medio = bytes([x for x in range(9, 16)])
        
        # 4. MANTENER PAYLOAD 0x10 a 0x37 (Bytes 16 al 55): Secuencia estándar de Linux/macOS
        relleno_final = bytes([x for x in range(16, 56)])
        
        # Ensamblamos el payload perfecto de 56 bytes
        payload = timestamp_bytes + byte_caracter + relleno_medio + relleno_final
        
        # Construimos el paquete manteniendo el Sequence Number coherente (seq=i+1)
        paquete = IP(dst=ip_destino) / ICMP(type=8, id=id_ping, seq=i+1) / Raw(load=payload)
        
        # Enviamos el paquete
        respuesta = sr1(paquete, timeout=2, verbose=0)
        
        if respuesta:
            print(f"[{i+1}/{len(texto_cifrado)}] Byte inyectado en la posición 8. Seq: {i+1}. Timestamp generado.")
        else:
            print(f"[{i+1}/{len(texto_cifrado)}] Tiempo de espera agotado.")
            
        # Simula el comportamiento humano/SO esperando 1 segundo exacto
        time.sleep(1)
        
    print("\nInyección finalizada. Revisa Wireshark para validar los campos.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Uso: sudo venv/bin/python pingv4.py "texto cifrado"')
        sys.exit(1)
        
    texto = sys.argv[1]
    enviar_ping_sigiloso(texto)