import sys
import time
import struct
import scapy.all as scapy
from cesar import cifrar_cesar

# Requerimiento 2: Importa la función cifrar_cesar de cesar.py
# Requerimiento 10: identification debe ser el número del proceso del sistema
id_ipv4 = id_icmp = scapy.RandShort()

# Requerimiento 9: Obtiene el valor del identifier desde un archivo
try:
    with open("identifier.txt", "r") as file:
        id_icmp = int(file.read())
except FileNotFoundError:
    id_icmp = 1

# Incrementa el identifier para el siguiente uso
with open("identifier.txt", "w") as file:
    file.write(str(id_icmp + 1))

# Requerimiento 1: Usa scapy
# Requerimiento 3: Timestamp en los primeros 8 bytes del payload
timestamp = struct.pack("<Q", int(time.time()))

# Requerimiento 4: Los siguientes 8 bytes son como un paquete ICMP
data_icmp = scapy.ICMP(id=0, seq=0).build()

# Requerimiento 5: Bytes desde 0x10 hasta 0x37
icmp_ping = bytes(range(0x10, 0x38))

# Requerimiento 6: Cifrar el mensaje
if len(sys.argv) != 4:
    print("Uso: python3 icmp_cesar.py <IP_destino> <mensaje> <corrimiento>")
    sys.exit(1)

ip_destino = sys.argv[1]
mensaje = sys.argv[2]
corrimiento = int(sys.argv[3])
mensaje_cifrado = cifrar_cesar(mensaje, corrimiento)

# Requerimiento 7: Las flags en IPv4 deben ser DF
# Requerimiento 8: Sequence number incremental (>=1) en el campo ICMP
packets = []
for i, caracter in enumerate(mensaje_cifrado):
    payload = timestamp + data_icmp + icmp_ping + caracter.encode()
    packet = scapy.IP(dst=ip_destino, id=id_ipv4, flags="DF") / scapy.ICMP(id=id_icmp, seq=i + 1) / payload
    packets.append(packet)

# Envía los paquetes
scapy.send(packets)

