import sys

def cifrar_cesar(texto, corrimiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            offset = 65 if caracter.isupper() else 97
            resultado += chr((ord(caracter) - offset + corrimiento) % 26 + offset)
        else:
            resultado += caracter
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <texto> <corrimiento>")
    else:
        texto = sys.argv[1]
        corrimiento = int(sys.argv[2])
        texto_cifrado = cifrar_cesar(texto, corrimiento)
        print(texto_cifrado)

