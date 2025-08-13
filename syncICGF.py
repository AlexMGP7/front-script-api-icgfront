# -*- coding: utf-8 -*-
"""
ICG Front Sync - Configuración cifrada con DPAPI (Windows)
- Almacena TODO el INI cifrado en config.enc (base64 de blob DPAPI)
- Migra automáticamente desde config.ini (antiguo con PWD_b64) si existe
- La GUI solo lee/escribe a través de la app
"""

import os
import sys
import io
import time
import base64
import threading
import tkinter as tk
from tkinter import messagebox
import configparser
import logging
from logging.handlers import RotatingFileHandler

import pyodbc
import schedule
from pystray import MenuItem as item, Icon as icon, Menu
from PIL import Image, ImageDraw, ImageFont

# --- DPAPI (Windows) ---
if sys.platform == 'win32':
    try:
        import win32crypt  # pywin32
    except Exception:
        win32crypt = None
else:
    win32crypt = None

# --- ESTADO GLOBAL DE LA APLICACIÓN ---
app_state = {
    "last_sync": "Nunca",
    "stop_event": threading.Event(),
    "tray_icon": None,
}

# --- CONFIGURACIÓN DE RUTAS ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE_LEGACY = os.path.join(BASE_DIR, 'config.ini')      # antiguo (sin cifrar)
CONFIG_FILE_ENC = os.path.join(BASE_DIR, 'config.enc')         # nuevo (cifrado)
LOG_FILE = os.path.join(BASE_DIR, "icg_front_sync.log")
ICON_FILE = os.path.join(BASE_DIR, 'icon.png')

# --- LOGGING ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(LOG_FILE, mode='a', maxBytes=1*1024*1024,
                                  backupCount=5, encoding='utf-8', delay=0)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger('icg_front_sync')
if not logger.handlers:
    logger.setLevel(logging.INFO)
    logger.addHandler(log_handler)
    
if getattr(sys, 'frozen', False):
    # Soporta --onefile con sys._MEIPASS
    BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- UTILIDADES DPAPI ---
def _ensure_dpapi():
    if sys.platform != 'win32' or win32crypt is None:
        raise RuntimeError("La protección DPAPI requiere Windows y el paquete 'pywin32'.")

def _dpapi_encrypt(plaintext: bytes, scope="user") -> str:
    """
    Cifra bytes con DPAPI. scope: 'user' (por defecto) o 'machine'.
    Devuelve base64 del blob cifrado para almacenarlo como texto.
    """
    _ensure_dpapi()
    entropy = b'ICGFrontSync v1'  # 'sal' adicional constante para la app
    flags = 0 if scope == 'user' else 0x4  # CRYPTPROTECT_LOCAL_MACHINE = 0x4
    encrypted_blob = win32crypt.CryptProtectData(plaintext, None, entropy, None, None, flags)
    return base64.b64encode(encrypted_blob).decode('utf-8')

def _dpapi_decrypt(b64cipher: str) -> bytes:
    """
    Descifra el base64 generado por _dpapi_encrypt y devuelve bytes en claro.
    """
    _ensure_dpapi()
    entropy = b'ICGFrontSync v1'
    encrypted_blob = base64.b64decode(b64cipher)
    # CryptUnprotectData -> (description, data)
    return win32crypt.CryptUnprotectData(encrypted_blob, entropy, None, None, 0)[1]

def _read_config_decrypted() -> configparser.ConfigParser:
    """
    Lee config.enc, descifra y devuelve un ConfigParser cargado.
    Lanza excepción si falla.
    """
    with open(CONFIG_FILE_ENC, 'r', encoding='utf-8') as f:
        b64 = f.read()
    plaintext = _dpapi_decrypt(b64)
    cfg = configparser.ConfigParser()
    cfg.read_string(plaintext.decode('utf-8'))
    return cfg

def _write_config_encrypted(cfg: configparser.ConfigParser, scope="user"):
    """
    Cifra todo el INI y lo guarda en config.enc (texto base64).
    """
    buf = io.StringIO()
    cfg.write(buf)
    cipher = _dpapi_encrypt(buf.getvalue().encode('utf-8'), scope=scope)
    with open(CONFIG_FILE_ENC, 'w', encoding='utf-8') as f:
        f.write(cipher)

def migrate_legacy_ini_if_needed():
    """
    Si hay config.ini con PWD_b64 y no hay config.enc, migrar y eliminar el .ini.
    """
    try:
        if os.path.exists(CONFIG_FILE_ENC):
            return
        if not os.path.exists(CONFIG_FILE_LEGACY):
            return

        legacy = configparser.ConfigParser()
        legacy.read(CONFIG_FILE_LEGACY, encoding='utf-8')

        # Normaliza el campo de password
        if 'Database' in legacy:
            if 'PWD_b64' in legacy['Database']:
                try:
                    pwd = base64.b64decode(legacy['Database']['PWD_b64']).decode('utf-8')
                except Exception:
                    pwd = legacy['Database']['PWD_b64']  # por si estaba en claro
                legacy['Database']['PWD'] = pwd
                legacy['Database'].pop('PWD_b64', None)

        _write_config_encrypted(legacy, scope="user")
        try:
            os.remove(CONFIG_FILE_LEGACY)
        except Exception:
            pass
        logger.info("Migración de config.ini -> config.enc completada.")
    except Exception as e:
        logger.error(f"Fallo migrando config.ini: {e}")

# --- INTERFAZ GRÁFICA DE CONFIGURACIÓN ---
def launch_config_gui():
    """Crea y muestra una ventana para guardar las credenciales y la info de la tienda (en cifrado)."""
    root = tk.Tk()
    root.title("Configuración de Conexión y Tienda")
    root.withdraw()
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_reqwidth()) / 2
    y = (root.winfo_screenheight() - root.winfo_reqheight()) / 2
    root.geometry(f"+{int(x)}+{int(y)}")
    root.deiconify()

    frame = tk.Frame(root, padx=15, pady=15)
    frame.pack(padx=10, pady=10)

    # --- Campos de BD ---
    tk.Label(frame, text="Servidor (IP o Nombre):").grid(row=0, column=0, sticky="w", pady=2)
    entry_server = tk.Entry(frame, width=40); entry_server.grid(row=0, column=1, pady=2)

    tk.Label(frame, text="Nombre Base de Datos:").grid(row=1, column=0, sticky="w", pady=2)
    entry_database = tk.Entry(frame, width=40); entry_database.grid(row=1, column=1, pady=2)

    tk.Label(frame, text="Usuario:").grid(row=2, column=0, sticky="w", pady=2)
    entry_user = tk.Entry(frame, width=40); entry_user.grid(row=2, column=1, pady=2)

    tk.Label(frame, text="Contraseña:").grid(row=3, column=0, sticky="w", pady=2)
    entry_password = tk.Entry(frame, width=40, show="*"); entry_password.grid(row=3, column=1, pady=2)

    # Separador visual
    tk.Frame(frame, height=2, bg="grey").grid(row=4, columnspan=2, pady=10, sticky="ew")

    # --- NUEVOS CAMPOS DE TIENDA ---
    tk.Label(frame, text="Marca (BBW/VS/LCW):").grid(row=5, column=0, sticky="w", pady=2)
    entry_marca = tk.Entry(frame, width=40); entry_marca.grid(row=5, column=1, pady=2)

    tk.Label(frame, text="País (PAN/COL/etc.):").grid(row=6, column=0, sticky="w", pady=2)
    entry_pais = tk.Entry(frame, width=40); entry_pais.grid(row=6, column=1, pady=2)

    tk.Label(frame, text="Tipo Tienda (Retail/Ecommerce):").grid(row=7, column=0, sticky="w", pady=2)
    entry_tipo = tk.Entry(frame, width=40); entry_tipo.grid(row=7, column=1, pady=2)

    # Precarga si existe config.enc
    try:
        if os.path.exists(CONFIG_FILE_ENC):
            cfg_pre = _read_config_decrypted()
            if 'Database' in cfg_pre:
                entry_server.insert(0, cfg_pre['Database'].get('Server', ''))
                entry_database.insert(0, cfg_pre['Database'].get('Database', ''))
                entry_user.insert(0, cfg_pre['Database'].get('UID', ''))
                # Por seguridad no precargamos la contraseña visible
            if 'StoreInfo' in cfg_pre:
                entry_marca.insert(0, cfg_pre['StoreInfo'].get('Marca', ''))
                entry_pais.insert(0, cfg_pre['StoreInfo'].get('Pais', ''))
                entry_tipo.insert(0, cfg_pre['StoreInfo'].get('TipoTienda', ''))
    except Exception as e:
        logger.warning(f"No se pudo precargar configuración: {e}")

    def save_settings():
        # Datos de la base de datos
        server = entry_server.get().strip()
        database = entry_database.get().strip()
        user = entry_user.get().strip()
        password = entry_password.get().strip()
        # Datos de la tienda
        marca = entry_marca.get().strip()
        pais = entry_pais.get().strip()
        tipo_tienda = entry_tipo.get().strip()

        if not all([server, database, user, password, marca, pais, tipo_tienda]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        config = configparser.ConfigParser()
        config['Database'] = {
            'Server': server,
            'Database': database,
            'UID': user,
            'PWD': password  # en claro dentro del INI en memoria; se cifra al guardar a disco
        }
        config['StoreInfo'] = {
            'Marca': marca,
            'Pais': pais,
            'TipoTienda': tipo_tienda
        }

        try:
            _write_config_encrypted(config, scope="user")  # usar "machine" si debe compartir entre usuarios del equipo
            messagebox.showinfo("Éxito", "Configuración guardada. Reinicie la aplicación para comenzar la sincronización.")
            root.destroy()
        except Exception as e:
            messagebox.showerror("Error al guardar", f"No se pudo escribir el archivo de configuración cifrado:\n{e}")

    save_button = tk.Button(frame, text="Guardar Configuración", command=save_settings, width=30)
    save_button.grid(row=8, columnspan=2, pady=20)

    root.mainloop()

# --- LÓGICA DE SINCRONIZACIÓN ---
def get_connection_string():
    """Descifra config.enc y construye la cadena de conexión."""
    try:
        cfg = _read_config_decrypted()
        db = cfg['Database']
        server, database, uid, pwd = db['Server'], db['Database'], db['UID'], db['PWD']

        # Detectar driver 18 o 17 (el que esté disponible)
        available = pyodbc.drivers()
        driver = next((d for d in ("ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server") if d in available), None)
        if driver is None:
            driver = "ODBC Driver 17 for SQL Server"  # fallback

        return f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};UID={uid};PWD={pwd}"
    except Exception as e:
        logger.error(f"Error al leer/descifrar la configuración de BD: {e}")
        return None

def get_store_info():
    """Descifra y lee la información de la tienda desde config.enc."""
    try:
        cfg = _read_config_decrypted()
        store = cfg['StoreInfo']
        return {
            'marca': store['Marca'],
            'pais': store['Pais'],
            'tipo_tienda': store['TipoTienda']
        }
    except Exception as e:
        logger.error(f"Error al leer la configuración de la tienda: {e}")
        return None

def get_data_from_front(connection_string):
    """Se conecta a la BD, ejecuta la consulta y devuelve los resultados. Incluye reintentos."""
    if not connection_string:
        logger.error("No se pudo obtener la cadena de conexión. Abortando consulta.")
        return None

    sql_query = """
    WITH VentasAgregadas AS (
        SELECT ALM.NOMBREALMACEN AS Tienda, FV.CAJA,
               COUNT(DISTINCT FV.NUMSERIE + '-' + CAST(FV.NUMFACTURA AS VARCHAR)) AS NumeroFacturas,
               SUM(AL.TOTAL) AS ImporteFacturas
        FROM FACTURASVENTA FV
        INNER JOIN ALBVENTACAB AC
            ON FV.NUMSERIE = AC.NUMSERIEFAC AND FV.NUMFACTURA = AC.NUMFAC AND FV.N = AC.NFAC
        INNER JOIN ALBVENTALIN AL
            ON AC.NUMSERIE = AL.NUMSERIE AND AC.NUMALBARAN = AL.NUMALBARAN AND AC.N = AL.N
        INNER JOIN ALMACEN ALM
            ON AL.CODALMACEN = ALM.CODALMACEN
        WHERE CAST(FV.FECHA AS DATE) = CAST(GETDATE() AS DATE)
        GROUP BY ALM.NOMBREALMACEN, FV.CAJA
    ), ComprasAgregadas AS (
        SELECT ALM.NOMBREALMACEN AS Tienda,
               COUNT(DISTINCT ACC.NUMSERIE + '-' + CAST(ACC.NUMALBARAN AS VARCHAR)) AS NumeroCompras,
               SUM(ACL.TOTAL) AS ImporteCompras
        FROM ALBCOMPRACAB ACC
        INNER JOIN ALBCOMPRALIN ACL
            ON ACC.NUMSERIE = ACL.NUMSERIE AND ACC.NUMALBARAN = ACL.NUMALBARAN AND ACC.N = ACL.N
        INNER JOIN ALMACEN ALM
            ON ACL.CODALMACEN = ALM.CODALMACEN
        WHERE CAST(ACC.FECHAALBARAN AS DATE) = CAST(GETDATE() AS DATE)
        GROUP BY ALM.NOMBREALMACEN
    ), Pendientes AS (
        SELECT RT.CAJA AS Caja, COUNT(RT.ID) AS TransaccionesPendientes
        FROM REM_TRANSACCIONES RT
        WHERE RT.IDCENTRAL = -1
        GROUP BY RT.CAJA
    ), TransaccionesTotales AS (
        SELECT RT.CAJA AS Caja, COUNT(RT.ID) AS TransaccionesGenerales
        FROM REM_TRANSACCIONES RT
        GROUP BY RT.CAJA
    ), MovimientosConsolidados AS (
        SELECT Tienda, Caja, NumeroFacturas, ImporteFacturas, 0 AS NumeroCompras, 0 AS ImporteCompras
        FROM VentasAgregadas
        UNION ALL
        SELECT Tienda, NULL AS Caja, 0 AS NumeroFacturas, 0 AS ImporteFacturas, NumeroCompras, ImporteCompras
        FROM ComprasAgregadas
    )
    SELECT MC.Tienda, MC.Caja,
           SUM(MC.NumeroFacturas) AS Numero_de_Facturas,
           SUM(MC.ImporteFacturas) AS Importe_Facturas,
           SUM(MC.NumeroCompras) AS Numero_de_Compras,
           SUM(MC.ImporteCompras) AS Importe_Compras,
           MAX(ISNULL(TT.TransaccionesGenerales, 0)) AS Transacciones_Totales,
           MAX(ISNULL(P.TransaccionesPendientes, 0)) AS Transacciones_Pendientes
    FROM MovimientosConsolidados MC
    LEFT JOIN Pendientes P ON MC.Caja = P.Caja
    LEFT JOIN TransaccionesTotales TT ON MC.Caja = TT.Caja
    GROUP BY MC.Tienda, MC.Caja
    ORDER BY MC.Tienda, MC.Caja;
    """

    for attempt in range(1, 4):
        try:
            with pyodbc.connect(connection_string, timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute(sql_query)
                columnas = [column[0] for column in cursor.description]
                datos_nuevos = [dict(zip(columnas, fila)) for fila in cursor.fetchall()]
            logger.info(f"Se obtuvieron {len(datos_nuevos)} registros (intento {attempt}).")
            app_state["last_sync"] = time.strftime('%d-%m-%Y %H:%M:%S')
            return datos_nuevos
        except Exception as e:
            logger.warning(f"Error al conectar o consultar la BD (intento {attempt}/3): {e}")
            time.sleep(2 * attempt)

    logger.error("Falló la consulta tras 3 intentos.")
    return None

# --- LÓGICA DE JOB ---
def job(connection_string):
    """Tarea de trabajo que se ejecuta en cada ciclo."""
    logger.info("--- Iniciando ciclo de sincronización ---")

    store_info = get_store_info()
    datos_rescatados = get_data_from_front(connection_string)

    if datos_rescatados:
        if store_info:
            logger.info(f"Contexto: Marca={store_info['marca']}, País={store_info['pais']}, Tipo={store_info['tipo_tienda']}")
        else:
            logger.warning("No se pudo cargar la información de la tienda desde config.enc.")

        logger.info(f"-> Se encontraron {len(datos_rescatados)} registros. Mostrando detalle:")
        for registro in datos_rescatados:
            logger.info(f"    {registro}")
        logger.info("--- Fin del detalle de datos ---")
    elif datos_rescatados == []:
        logger.info("-> La consulta se ejecutó, pero no se encontraron registros para la fecha actual.")
    else:
        logger.warning("-> No se rescataron datos en este ciclo. Revisa logs de errores anteriores.")

    logger.info("--- Ciclo de sincronización finalizado ---")

# --- LÓGICA DE LA BANDEJA DEL SISTEMA ---
def create_image():
    """Crea una imagen genérica si icon.png no existe."""
    if os.path.exists(ICON_FILE):
        try:
            return Image.open(ICON_FILE)
        except Exception as e:
            logger.warning(f"No se pudo abrir icon.png: {e}. Usando icono por defecto.")

    # Icono simple por defecto
    width = 64
    height = 64
    image = Image.new('RGB', (width, height), color='darkgrey')
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except Exception:
        font = ImageFont.load_default()
    # Centrar la "S"
    try:
        bbox = draw.textbbox((0, 0), "S", font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    except Exception:
        # Compatibilidad con Pillow antiguo
        tw, th = draw.textsize("S", font=font)
    draw.text(((width - tw) // 2, (height - th) // 2), "S", fill="white", font=font)
    return image

def run_scheduler_thread(connection_string):
    """Hilo que ejecuta las tareas programadas."""
    job_with_conn = lambda: job(connection_string)

    schedule.every(15).minutes.do(job_with_conn)

    logger.info("Servicio de sincronización iniciado. Primera ejecución inmediata.")
    job_with_conn()

    while not app_state["stop_event"].is_set():
        schedule.run_pending()
        time.sleep(1)
    logger.info("Hilo de scheduler detenido.")

def get_menu(connection_string):
    """Genera el menú dinámico para el icono de la bandeja."""
    def force_sync(icon_obj, menu_item):
        logger.info("Sincronización manual solicitada.")
        threading.Thread(target=job, args=(connection_string,), daemon=True).start()

    def open_config(icon_obj, menu_item):
        logger.info("Apertura de configuración solicitada.")
        threading.Thread(target=launch_config_gui, daemon=True).start()

    def _exit(icon_obj, menu_item):
        exit_app(icon_obj, menu_item)

    yield item(lambda i: f'Última Sincronización: {app_state["last_sync"]}', None, enabled=False)
    yield Menu.SEPARATOR
    yield item('Sincronizar Ahora', force_sync)
    yield item('Configurar...', open_config)
    yield item('Salir', _exit)

def exit_app(icon_obj, _menu_item):
    """Detiene los hilos y cierra la aplicación."""
    logger.info("Solicitud de salida recibida.")
    app_state["stop_event"].set()
    try:
        icon_obj.stop()
    except Exception as e:
        logger.debug(f"Error al detener icono: {e}")
    logger.info("Aplicación cerrada.")

# --- PUNTO DE ENTRADA PRINCIPAL ---
if __name__ == "__main__":
    # Migrar desde .ini si aplica
    migrate_legacy_ini_if_needed()

    if not os.path.exists(CONFIG_FILE_ENC):
        logger.warning(f"No se encontró '{CONFIG_FILE_ENC}'. Iniciando GUI de configuración.")
        try:
            launch_config_gui()
            logger.info("Configuración no encontrada. El programa se cerrará.")
            sys.exit("Configuración guardada. Por favor, reinicie la aplicación.")
        except Exception as e:
            logger.error(f"No se pudo abrir la GUI de configuración: {e}")
            # Mensaje claro si falta DPAPI/pywin32
            if sys.platform != 'win32' or win32crypt is None:
                sys.exit("Esta aplicación requiere Windows y el paquete 'pywin32' para cifrado DPAPI.")
            sys.exit(1)

    logger.info(f"Archivo de configuración cifrado '{CONFIG_FILE_ENC}' encontrado. Iniciando servicio.")
    conn_str = get_connection_string()

    if conn_str:
        image = create_image()
        tray_icon = icon(
            'SyncICGFront',
            image,
            'Sincronizador ICG Front',
            menu=Menu(lambda: get_menu(conn_str))
        )
        app_state['tray_icon'] = tray_icon

        scheduler_thread = threading.Thread(target=run_scheduler_thread, args=(conn_str,), daemon=True)
        scheduler_thread.start()

        # Bloquea hasta que se cierre el icono
        try:
            tray_icon.run()
        finally:
            # Cierre limpio
            app_state["stop_event"].set()
            schedule.clear()
            try:
                scheduler_thread.join(timeout=5)
            except Exception:
                pass

    else:
        logger.error("No se pudo iniciar. El archivo de configuración es inválido o no se pudo descifrar.")
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error de Configuración", "No se pudo iniciar. 'config.enc' es inválido o no se pudo descifrar.\nBorre el archivo para reconfigurar.")
        root.destroy()
        sys.exit("Error en la configuración.")
