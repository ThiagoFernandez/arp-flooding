# arp-flooding

> ⚠️ **Herramienta ofensiva de laboratorio.** Inunda un switch con miles de direcciones MAC
> falsas para desbordar su tabla CAM. Puede tirar la conectividad de **todo el segmento de red**.
> Usala **únicamente en una red propia y aislada** — un laboratorio virtual o una VLAN de pruebas
> que controles vos. Correrla en una red ajena (el trabajo, la facultad, un bar) es ilegal en la
> mayoría de las jurisdicciones. El uso que le des es tu responsabilidad.

Generador de **inundación de tabla CAM (MAC flooding)** escrito en Python con Scapy. Emite ARP
replies gratuitos en broadcast, cada uno con una dirección MAC de origen distinta y aleatoria, a
un ritmo de 1–20 ms. Al variar la MAC de origen en cada trama, fuerza al switch a aprender miles
de MAC inexistentes hasta llenar su tabla de direcciones.

---

## Qué hace

Un bucle infinito que, en cada vuelta:

1. Fabrica una **MAC de origen falsa** — elige uno de tres prefijos de fabricante (OUI) y le pega 3 bytes aleatorios con `RandMAC()`.
2. Genera una **IP de origen aleatoria** dentro de `192.168.0.0/24`.
3. Arma la trama `Ether(src=MAC_falsa, dst=broadcast) / ARP(op=2) / Padding(18 bytes)` y la envía en capa 2 con `sendp()`.
4. Espera un intervalo aleatorio de 1 a 20 ms.

`op=2` es un ARP *reply*; un reply que nadie pidió es un **ARP gratuito**.

---

## Qué ataque es

El diferencial está en que **la MAC de origen del Ethernet cambia en cada trama**. El switch
aprende cada MAC nueva en su tabla CAM; miles por segundo la desbordan. Cuando se llena, muchos
switches entran en *fail-open* y empiezan a reenviar todo por todos los puertos (se comportan como
un hub) — lo que permite espiar el tráfico ajeno del segmento. Es el MAC flooding clásico (estilo
`macof`).

Como efecto secundario, los ARP gratuitos con pares IP↔MAC inventados ensucian las tablas ARP de
los hosts.

---

## Requisitos

- **Python 3.x**
- **Scapy** — `pip install scapy`
- Permisos de **administrador / root** (se envían tramas crudas en capa 2)
- En **Windows**: **Npcap** instalado (con soporte raw)
- Un **switch real** (físico o virtual) contra el cual probar — contra un solo host o un hub no tiene sentido

---

## Uso

```bash
sudo python main.py        # Linux
```

En Windows, PowerShell **como administrador**:

```powershell
python main.py
```

Imprime cada MAC falsa a medida que la envía. Se corta con `Ctrl+C`.

> ⚠️ Antes de correrlo, releé el aviso del principio.

---

## La contramedida

El MAC flooding se contiene en el switch con **port security**: limitar cuántas MAC se aprenden por
puerto y qué hacer al excederse (`shutdown` / `restrict`). Es la defensa que se estudia en CCNA 2
(seguridad de LAN). Tener el ataque en código y la defensa en el switch cierra el par
atacar / mitigar.

---

## Limitaciones y próximos pasos

- La subred (`192.168.0.`), el ritmo y la lista de vendors están **hardcodeados**: el paso natural
  es pasarlos por `argparse` (subred, paquetes por segundo, duración).
- No mide el efecto: una buena demo sería mostrar el "antes / después" de lo que ve un tercer host
  cuando el switch entra en fail-open.
