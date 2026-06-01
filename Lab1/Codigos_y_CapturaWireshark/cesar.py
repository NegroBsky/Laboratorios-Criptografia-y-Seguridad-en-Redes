import sys

def cifrar_cesar(texto, desplazamiento):
    resultado = ""
    
    for caracter in texto:
        # Verificamos si el caracter es una letra del alfabeto
        if caracter.isalpha():
            # Definimos la base ASCII dependiendo de si es mayúscula o minúscula
            base = ord('A') if caracter.isupper() else ord('a')
            
            # Aplicamos la fórmula matemática del cifrado César
            indice = ord(caracter) - base
            nuevo_indice = (indice + desplazamiento) % 26
            nuevo_caracter = chr(nuevo_indice + base)
            
            resultado += nuevo_caracter
        else:
            # Si no es una letra (como espacios o números), lo dejamos igual
            resultado += caracter
            
    return resultado

if __name__ == "__main__":
    # Validamos que se entreguen exactamente 2 parámetros adicionales al nombre del script
    if len(sys.argv) != 3:
        print('Uso: python3 cesar.py "texto a cifrar" <desplazamiento>')
        sys.exit(1)
        
    texto_ingresado = sys.argv[1]
    
    try:
        desplazamiento_ingresado = int(sys.argv[2])
    except ValueError:
        print("Error: El parámetro de desplazamiento debe ser un número entero.")
        sys.exit(1)
        
    texto_cifrado = cifrar_cesar(texto_ingresado, desplazamiento_ingresado)
    print(texto_cifrado)