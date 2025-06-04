Propósito General del Script wifi_toolkit.py

Este script es una herramienta de línea de comandos diseñada para realizar varias tareas relacionadas con la auditoría de redes Wi-Fi. Sus principales capacidades son:

Escaneo de Redes Wi-Fi: Para identificar puntos de acceso (APs) cercanos.
Ataque de Deautenticación: Para simular un ataque que desconecta a un cliente específico o a todos los clientes de un punto de acceso. Esta función es útil para probar la resiliencia de una red.
Detección de WPS (Wi-Fi Protected Setup): Para encontrar redes que tengan WPS habilitado, identificando versiones y si está bloqueado, lo cual puede ser un vector de vulnerabilidad.
El script está diseñado para ser relativamente fácil de usar a través de un menú interactivo y se esfuerza por dejar la interfaz de red en su estado original (modo "managed") después de su ejecución.

Requisitos Previos para Ejecutar el Script

Antes de usar el script, asegúrate de cumplir con lo siguiente:

Privilegios de Root: El script necesita acceso de bajo nivel a la interfaz de red, por lo que debe ejecutarse con privilegios de superusuario (root). Generalmente, esto se hace anteponiendo sudo al comando de ejecución. El script verifica esto al inicio.
Herramientas del Sistema:
ip: Utilidad estándar de Linux para configuración de red.
iw: Utilidad estándar de Linux para configurar interfaces inalámbricas.
iwconfig (opcional, como fallback): El script puede intentar usar iwconfig si iw falla para poner la interfaz en modo monitor, aunque advierte si no lo encuentra.
wash: Necesaria para la función de "Detección de WPS". Esta herramienta forma parte del paquete reaver. Si no está instalada, esa opción del menú no funcionará correctamente.
Librería Scapy de Python: Esencial para la funcionalidad de "Ataque de Deautenticación". Si Scapy no está instalada, esta opción no estará disponible. El script verifica su presencia al inicio e informa si falta. Puedes instalarla generalmente con pip install scapy.
Interfaz Wi-Fi Compatible: Necesitas una tarjeta Wi-Fi que soporte el "modo monitor" para las funciones de ataque y detección de WPS. No todas las tarjetas lo soportan, o pueden requerir drivers específicos.
Cómo Ejecutar el Script y sus Flags (Argumentos)

Para ejecutar el script, abrirás una terminal y usarás un comando similar a:

Bash

sudo python3 deauth.py [FLAGS/ARGUMENTOS]
El script acepta los siguientes argumentos de línea de comandos (flags):

-i INTERFACE o --interface INTERFACE:

Propósito: Especifica qué interfaz de red Wi-Fi deseas utilizar (por ejemplo, wlan0, wlan1mon).
Valor por defecto: Si no proporcionas este flag, el script usará wlan0 por defecto.
Ejemplo: sudo python3 deauth.py -i wlan1
-c COUNT o --count COUNT:

Propósito: (Específico para el Ataque de Deautenticación) Define cuántos paquetes de deautenticación se enviarán al objetivo.
Valor por defecto: 1000 paquetes.
Ejemplo: sudo python3 deauth.py -i wlan0 -c 500 (para enviar 500 paquetes)
--interval INTERVAL:

Propósito: (Específico para el Ataque de Deautenticación) Establece el tiempo de espera (en segundos) entre el envío de cada paquete de deautenticación.
Valor por defecto: 0.1 segundos.
Ejemplo: sudo python3 deauth.py -i wlan0 --interval 0.05 (para un envío más rápido)
Menú Principal del Script

Una vez ejecutado y después de las verificaciones iniciales, el script presentará un menú principal con las siguientes opciones:

╔══════════════════════════════╗
║       WiFi Toolkit Menú      ║
╠══════════════════════════════╣
║ 1. Ataque de Deautenticación ║
║ 2. Detección de WPS          ║
║ 3. Salir                     ║
╚══════════════════════════════╝
Selecciona una opción (1-3):
Debes ingresar el número de la acción que deseas realizar.

Funcionalidad 1: Ataque de Deautenticación (Opción 1)

Esta función simula un ataque que puede desconectar dispositivos de una red Wi-Fi. Funciona de la siguiente manera:

Preparación Inicial de la Interfaz:
La interfaz especificada (-i) se configura temporalmente en modo "managed" (modo normal de cliente Wi-Fi) para poder escanear redes disponibles.
Escaneo de Puntos de Acceso (APs):
Utiliza el comando iw dev <interfaz> scan para buscar redes Wi-Fi cercanas.
Muestra una lista numerada de los APs encontrados, incluyendo su SSID (nombre de la red), BSSID (dirección MAC del AP), banda de frecuencia y canal.
Selección del AP Objetivo:
Se te pedirá que ingreses el ID (número de la lista) del AP al que deseas dirigir el ataque.
Especificación del Cliente (Opcional):
Podrás ingresar la dirección MAC del dispositivo cliente específico que quieres desconectar.
Si presionas ENTER sin ingresar una MAC, el ataque se dirigirá a todos los clientes conectados a ese AP (dirección de broadcast ff:ff:ff:ff:ff:ff).
Preparación Final de la Interfaz para el Ataque:
La interfaz Wi-Fi se configura en modo monitor. Este modo es crucial ya que permite a la tarjeta Wi-Fi capturar y enviar paquetes sin estar asociada a un AP.
La interfaz se sintoniza al mismo canal que el AP objetivo para asegurar que los paquetes lleguen correctamente.
Envío de Paquetes de Deautenticación:
Usando la librería Scapy, el script construye y envía los paquetes de deautenticación.
Estos paquetes parecen provenir del AP y le dicen al cliente (o clientes) que se desconecten.
Se enviará el número de paquetes especificado por --count con el intervalo --interval.
Puedes presionar Ctrl+C para detener el envío antes de que se completen todos los paquetes.
Finalización del Ataque:
Una vez enviados todos los paquetes (o si se interrumpe), se mostrará un mensaje.
El script luego terminará (y gracias a la función atexit, intentará restaurar la interfaz a modo managed).
Funcionalidad 2: Detección de WPS (Opción 2)

Wi-Fi Protected Setup (WPS) es un estándar de seguridad que intenta simplificar la conexión de dispositivos a una red, pero ciertas implementaciones pueden ser vulnerables. Esta función te ayuda a identificarlas:

Verificación de wash:
El script primero comprueba si la herramienta wash está instalada en tu sistema. Si no, te informará y no podrá continuar con esta opción.
Preparación de la Interfaz:
La interfaz Wi-Fi especificada (-i) se pone en modo monitor, ya que wash lo requiere para escanear las tramas "beacon" de los APs que anuncian información de WPS.
Ejecución de wash:
El script ejecuta el comando wash -i <interfaz> -C durante un tiempo predefinido (WASH_SCAN_DURATION, por defecto 45 segundos). El flag -C le dice a wash que ignore errores de FCS (Frame Check Sequence).
wash escaneará todos los canales buscando APs que tengan WPS habilitado.
Parseo y Muestra de Resultados:
La salida de wash es procesada por el script.
Se muestra una tabla con las redes que tienen WPS, incluyendo: BSSID, Canal, RSSI (potencia de la señal), Versión de WPS, si WPS está Bloqueado (Locked) y el ESSID (nombre de la red).
El script destaca las redes que tienen WPS habilitado y NO bloqueado (WPS Locked: No), ya que estas son potencialmente más vulnerables a ataques como Pixie Dust o fuerza bruta de PIN.
Finalización:
Tras mostrar los resultados, la función termina. El script principal también terminará, restaurando la interfaz.
Manejo de Errores y Limpieza

El script incluye varias características para ser más robusto y amigable:

Verificación de Herramientas: Comprueba la existencia de comandos necesarios (ip, iw, wash) antes de intentar usarlos.
Restauración de Interfaz:
Utiliza atexit.register(restore_managed, iface) para asegurar que la función restore_managed se llame cuando el script esté por terminar, ya sea normalmente o por un error no capturado. Esta función intenta devolver la interfaz a modo "managed" y activarla.
También captura señales como SIGINT (Ctrl+C) y SIGTERM para ejecutar la limpieza antes de salir.
Manejo de Excepciones: Varios bloques try...except están presentes para capturar errores comunes durante operaciones de red o ejecución de subprocesos, mostrando mensajes informativos en lugar de simplemente fallar.
Verificación de Interfaz de Red: Confirma que la interfaz de red especificada realmente existe en el sistema.
Para el Usuario Final: Consejos y Advertencias

Uso Ético y Legal: Este script es una herramienta de auditoría. Úsalo de manera responsable y solo en redes para las cuales tengas permiso explícito para probar. Realizar ataques de deautenticación o intentar explotar WPS en redes ajenas es ilegal en la mayoría de las jurisdicciones.
Entiende lo que Haces: Antes de seleccionar una opción, asegúrate de comprender qué acción va a realizar el script y sus posibles consecuencias.
Compatibilidad de Hardware: El éxito de las operaciones, especialmente aquellas que requieren modo monitor (deauth, detección WPS), depende en gran medida de tu tarjeta Wi-Fi y sus drivers. No todas las tarjetas son compatibles o pueden funcionar de manera inconsistente.
Interferencias y Entorno: El entorno Wi-Fi (distancia, obstáculos, otras redes) puede afectar los resultados del escaneo y la efectividad de los ataques.
