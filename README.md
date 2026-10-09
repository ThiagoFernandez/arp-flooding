# arp-flooding

> ⚠️ **Herramienta ofensiva de laboratorio.** Inunda un switch con miles de direcciones MAC
> falsas para desbordar su tabla CAM. Puede tirar la conectividad de **todo el segmento de red**.
> Usala **únicamente en una red propia y aislada** — un laboratorio virtual o una VLAN de pruebas
> que controles vos. Correrla en una red ajena (el trabajo, la facultad, un bar) es ilegal en la
> mayoría de las jurisdicciones. El uso que le des es tu responsabilidad.

Generador de **inundación de tabla CAM (MAC flooding)** escrito en Python con Scapy. Emite ARP
replies gratuitos en broadcast, cada uno con una dirección MAC de origen distinta y aleatoria. Al
variar la MAC de origen en cada trama, fuerza al switch a aprender miles de MAC inexistentes hasta
llenar su tabla de direcciones.

---

## Qué hace

Un bucle que, en cada vuelta:

1. Fabrica una **MAC de origen falsa** — elige al azar un prefijo de fabricante (OUI) de la base
   oficial de la IEEE y le pega 3 bytes aleatorios con `RandMAC()`.
2. Genera una **IP de origen aleatoria** dentro de la red que le pasás (evitando la dirección de
   red y la de broadcast).
3. Arma la trama `Ether(src=MAC_falsa, dst=broadcast) / ARP(op=2) / Padding(18 bytes)` y la envía
   en capa 2 por un socket que abre una sola vez.
4. Espera `1 / rate` segundos y repite.

`op=2` es un ARP *reply*; un reply que nadie pidió es un **ARP gratuito**.

Al arrancar descarga el registro **OUI oficial de la IEEE** (`standards-oui.ieee.org`). Si falla la
descarga, usa una lista de OUIs pre-cargados (Cisco, Apple, Intel, VMware, etc.).

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

```
python main.py <red/máscara> -i <interfaz> [-r pps] [-d segundos]
```

Argumentos:

| Argumento          | Obligatorio | Default    | Qué es                                                        |
| ------------------ | ----------- | ---------- | ------------------------------------------------------------- |
| `red`              | sí          | —          | Red y máscara, ej. `10.10.10.0/24`. Debe ser **privada**.     |
| `-i`, `--iface`    | sí          | —          | Interfaz de red por la que sale el ataque.                    |
| `-r`, `--rate`     | no          | `1000`     | Paquetes por segundo.                                         |
| `-d`, `--duracion` | no          | `0`        | Duración en segundos (`0` = infinito, se corta con `Ctrl+C`). |

La red se valida: solo acepta rangos **privados** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

Linux:

```bash
sudo python main.py 192.168.1.0/24 -i eth0 -r 5000
```

Windows, PowerShell **como administrador**:

```powershell
python main.py 192.168.1.0/24 -i "Ethernet" -r 5000 -d 30
```

Al terminar imprime el total de MACs enviadas. Se corta con `Ctrl+C`.

> ⚠️ Antes de correrlo, releé el aviso del principio.

---

## Cómo averiguar el nombre de la interfaz

El valor que va en `-i` es el nombre que usa Scapy para esa placa. Para listarlos:

**Windows** (PowerShell como admin):

```powershell
python -c "from scapy.all import show_interfaces; show_interfaces()"
```

Tomá el nombre de la columna *name* (ej. `Ethernet`, `Wi-Fi`). También sirve de referencia:

```powershell
Get-NetAdapter
```

**Linux:**

```bash
ip link
```

(usá el nombre tipo `eth0`, `ens33`, `wlan0`).

---

## Cómo ver el efecto en el switch

Para comprobar que la tabla CAM se está llenando, en un **switch Cisco** (consola / Packet Tracer):

```
show mac address-table
```

Y para ver el conteo (cuántas direcciones aprendió / cuántas le quedan):

```
show mac address-table count
```

Con el ataque corriendo vas a ver la tabla llenarse de MAC desconocidas en el puerto donde está
conectada la máquina atacante.

---

## La contramedida

El MAC flooding se contiene en el switch con **port security**: limitar cuántas MAC se aprenden por
puerto y qué hacer al excederse (`shutdown` / `restrict`). Es la defensa que se estudia en CCNA 2
(seguridad de LAN). Tener el ataque en código y la defensa en el switch cierra el par
atacar / mitigar.

---

## Limitaciones y próximos pasos

- No mide el efecto automáticamente: una buena demo sería mostrar el "antes / después" de lo que ve
  un tercer host cuando el switch entra en fail-open.
- La MAC de origen se arma con OUI real + 3 bytes aleatorios; se podría randomizar también el OUI
  completo para mayor variedad.
