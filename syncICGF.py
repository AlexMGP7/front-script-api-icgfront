# -*- coding: utf-8 -*-
"""
ICG Front Sync - Configuración cifrada con DPAPI (Windows) + Directorios saneados + Scheduler eficiente
- Almacena TODO el INI cifrado en config.enc (base64 de blob DPAPI) en %LOCALAPPDATA%\ICGFrontSync
- Migra automáticamente desde config.ini legado (ubicaciones antiguas) si existe
- GUI solo lee/escribe a través de la app
- SIN ODBC: usa pymssql (driver puro) para SQL Server
"""

import os
import sys
import io
import time
import base64
import threading
import tkinter as tk
import hashlib
from tkinter import messagebox, simpledialog
import configparser
import logging
from logging.handlers import RotatingFileHandler

import json
import requests ### NUEVO ###

# --- BBDD: SIN ODBC (pymssql) ---
try:
    import pymssql  # pip install pymssql
except Exception:
    pymssql = None

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

# --- NOMBRE APP Y DIRECTORIOS ---
APP_NAME = "ICGFrontSync"

# Directorio de RECURSOS (solo lectura, donde viven los assets empaquetados)
RESOURCE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
# Directorio de EJECUCIÓN (donde está el exe/py; útil para migración legado)
EXEC_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))

# Directorio de DATOS (lectura/escritura segura por usuario)
DATA_DIR = os.path.join(os.environ.get('LOCALAPPDATA', EXEC_DIR), APP_NAME)
os.makedirs(DATA_DIR, exist_ok=True)

# Rutas de archivos
CONFIG_FILE_ENC = os.path.join(DATA_DIR, 'config.enc')               # nuevo (cifrado)
CONFIG_FILE_LEGACY = os.path.join(DATA_DIR, 'config.ini')            # legado posible (en DATA_DIR)
CONFIG_FILE_LEGACY_OLD = os.path.join(EXEC_DIR, 'config.ini')        # legado antiguo (junto al exe/py viejo)
CONFIG_KEY_FILE = os.path.join(DATA_DIR, 'admin.key.enc')
LOG_FILE = os.path.join(DATA_DIR, "icg_front_sync.log")
ICON_FILE = os.path.join(RESOURCE_DIR, 'icon.png')

# --- ESTADO GLOBAL DE LA APLICACIÓN ---
app_state = {
    "last_sync": "Nunca",
    "stop_event": threading.Event(),
    "tray_icon": None,
    "interval_minutes": 15,  # >>> NUEVO: intervalo por defecto
}


# --- LOGGING ---
def _setup_logging():
    logger = logging.getLogger('icg_front_sync')
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    try:
        log_handler = RotatingFileHandler(LOG_FILE, mode='a', maxBytes=1*1024*1024,
                                          backupCount=5, encoding='utf-8', delay=0)
    except Exception:
        # Si por alguna razón falla el archivo (permisos, etc.), baja a consola
        log_handler = logging.StreamHandler()
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)
    return logger

logger = _setup_logging()

# --- UTILIDADES DPAPI ---
def _ensure_dpapi():
    if sys.platform != 'win32' or win32crypt is None:
        raise RuntimeError("La protección DPAPI requiere Windows y el paquete 'pywin32'.")

def _dpapi_encrypt(plaintext: bytes, scope: str = "user") -> str:
    """
    Cifra bytes con DPAPI. scope: 'user' (por defecto) o 'machine'.
    Devuelve base64 (str) del blob cifrado para almacenarlo como texto.

    Importante:
    - Usamos 'optional entropy' constante para la app. Debe coincidir en Protect/Unprotect.
    """
    _ensure_dpapi()
    entropy = b'ICGFrontSync v1'  # 'sal' adicional constante
    flags = 0 if scope == 'user' else 0x4  # CRYPTPROTECT_LOCAL_MACHINE = 0x4
    encrypted_blob = win32crypt.CryptProtectData(plaintext, None, entropy, None, None, flags)
    return base64.b64encode(encrypted_blob).decode('utf-8')

# --- NUEVA FUNCIÓN: construir el payload JSON ---
def _build_json_payload(rows, store_info):
    """
    Construye el payload JSON enriqueciendo los registros de la base de datos
    con la información de la tienda (país, tipo, marca).
    """
    pais = (store_info or {}).get('pais')
    tipo = (store_info or {}).get('tipo_tienda')
    marca = (store_info or {}).get('marca')  # Obtener la marca
    
    enriched = [
        {
            "Marca": marca,  # Añadir la marca desde la configuración
            "Tienda": row.get("Tienda"),
            "Caja": row.get("Caja"),
            "Numero_de_Facturas": row.get("Numero_de_Facturas"),
            "Importe_Facturas": row.get("Importe_Facturas"),
            "Numero_de_Compras": row.get("Numero_de_Compras"),
            "Importe_Compras": row.get("Importe_Compras"),
            "Transacciones_Totales": row.get("Transacciones_Totales"),
            "Transacciones_Pendientes": row.get("Transacciones_Pendientes"),
            "Pais": pais,
            "Tipo_Tienda": tipo
        } for row in (rows or [])
    ]
    return {"Registros": enriched}


def _dpapi_decrypt(b64cipher: str) -> bytes:
    """
    Descifra el base64 generado por _dpapi_encrypt y devuelve bytes en claro.
    Orden correcto de argumentos: (Data, OptionalEntropy, Reserved, PromptStruct, Flags)
    """
    _ensure_dpapi()
    entropy = b'ICGFrontSync v1'
    encrypted_blob = base64.b64decode(b64cipher)
    try:
        # Correcto: la entropy va en el 2º argumento
        return win32crypt.CryptUnprotectData(encrypted_blob, entropy, None, None, 0)[1]
    except Exception:
        # Compatibilidad: intenta sin entropy por si el archivo se creó sin ella
        return win32crypt.CryptUnprotectData(encrypted_blob, None, None, None, 0)[1]

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

def _write_config_encrypted(cfg: configparser.ConfigParser, scope: str = "user"):
    """
    Cifra todo el INI y lo guarda en config.enc (texto base64).
    """
    buf = io.StringIO()
    cfg.write(buf)
    cipher = _dpapi_encrypt(buf.getvalue().encode('utf-8'), scope=scope)
    with open(CONFIG_FILE_ENC, 'w', encoding='utf-8') as f:
        f.write(cipher)
        
def _hash_key(key_str: str) -> str:
    # Hash simple (DPAPI ya cifra en disco). Añadimos un "pepper" constante.
    pepper = b'ICGFrontSync-ADMIN-PEPPER'
    h = hashlib.sha256()
    h.update(key_str.encode('utf-8') + pepper)
    return h.hexdigest()

def _write_admin_key(key_str: str):
    digest = _hash_key(key_str).encode('utf-8')
    cipher = _dpapi_encrypt(digest, scope="user")
    with open(CONFIG_KEY_FILE, 'w', encoding='utf-8') as f:
        f.write(cipher)

def _read_admin_key_digest() -> str | None:
    try:
        with open(CONFIG_KEY_FILE, 'r', encoding='utf-8') as f:
            b64 = f.read()
        plain = _dpapi_decrypt(b64).decode('utf-8')
        return plain
    except Exception:
        return None

def _verify_admin_key(candidate: str) -> bool:
    saved = _read_admin_key_digest()
    if not saved:
        return False
    return _hash_key(candidate) == saved

def _get_config_interval(default: int = 15) -> int:
    try:
        cfg = _read_config_decrypted()
        return int(cfg.get('Schedule', 'IntervalMinutes', fallback=default))
    except Exception:
        return default

def _set_config_interval(minutes: int) -> None:
    try:
        cfg = _read_config_decrypted()
        if 'Schedule' not in cfg:
            cfg['Schedule'] = {}
        cfg['Schedule']['IntervalMinutes'] = str(minutes)
        _write_config_encrypted(cfg, scope="user")
        logger.info(f"Intervalo guardado en config.enc: {minutes} minutos.")
    except Exception as e:
        logger.error(f"No se pudo guardar el intervalo en config.enc: {e}")

def _bootstrap_admin_key_ui() -> bool:
    """
    Abre un diálogo para crear la clave la primera vez (o si falta el fichero).
    Devuelve True si se creó, False si el usuario canceló.
    """
    root = tk.Tk(); root.withdraw()
    try:
        while True:
            k1 = simpledialog.askstring("Crear clave de administración",
                                        "Crea una clave para proteger la configuración:",
                                        show="*", parent=root)
            if k1 is None:
                return False
            if len(k1.strip()) < 4:
                messagebox.showerror("Clave demasiado corta", "Usa al menos 4 caracteres.")
                continue
            k2 = simpledialog.askstring("Confirmar clave",
                                        "Repite la clave:",
                                        show="*", parent=root)
            if k2 is None:
                return False
            if k1 != k2:
                messagebox.showerror("No coincide", "Las claves no coinciden. Inténtalo de nuevo.")
                continue
            _write_admin_key(k1)
            messagebox.showinfo("Clave guardada", "La clave de administración se ha establecido.")
            return True
    finally:
        root.destroy()

def _require_admin_key_then(action_callable):
    """
    Pide la clave (o la crea si no existe) y si es correcta ejecuta 'action_callable'.
    """
    root = tk.Tk(); root.withdraw()
    try:
        # Si no hay clave, pedir crearla
        if not os.path.exists(CONFIG_KEY_FILE):
            created = _bootstrap_admin_key_ui()
            if not created:
                return
        # Pedir clave para continuar
        k = simpledialog.askstring("Clave de administración",
                                   "Introduce la clave para configurar:",
                                   show="*", parent=root)
        if k is None:
            return
        if not _verify_admin_key(k):
            messagebox.showerror("Clave incorrecta", "La clave no es válida.")
            return
        # Clave OK → ejecutar acción
        action_callable()
    finally:
        root.destroy()

def migrate_legacy_ini_if_needed():
    """
    Si hay config.ini con PWD_b64 y no hay config.enc, migrar y eliminar el/los ini(s) legado(s).
    Busca en DATA_DIR y en EXEC_DIR para compatibilidad hacia atrás.
    """
    try:
        if os.path.exists(CONFIG_FILE_ENC):
            return

        candidates = []
        if os.path.exists(CONFIG_FILE_LEGACY):
            candidates.append(CONFIG_FILE_LEGACY)
        if os.path.exists(CONFIG_FILE_LEGACY_OLD):
            candidates.append(CONFIG_FILE_LEGACY_OLD)

        if not candidates:
            return

        # Usa el primero que exista (preferencia por DATA_DIR)
        src_ini = candidates[0]
        legacy = configparser.ConfigParser()
        legacy.read(src_ini, encoding='utf-8')

        # Normaliza password desde PWD_b64
        if 'Database' in legacy:
            if 'PWD_b64' in legacy['Database']:
                try:
                    pwd = base64.b64decode(legacy['Database']['PWD_b64']).decode('utf-8')
                except Exception:
                    pwd = legacy['Database']['PWD_b64']  # por si estaba en claro
                legacy['Database']['PWD'] = pwd
                legacy['Database'].pop('PWD_b64', None)

        _write_config_encrypted(legacy, scope="user")

        # Intenta remover INIs legado
        for path in candidates:
            try:
                os.remove(path)
            except Exception:
                pass

        logger.info(f"Migración de config.ini -> config.enc completada desde {src_ini} a {CONFIG_FILE_ENC}.")
    except Exception as e:
        logger.exception(f"Fallo migrando config.ini: {e}")

# --- INTERFAZ GRÁFICA DE CONFIGURACIÓN ---
def launch_config_gui():
    """Crea y muestra una ventana para guardar las credenciales y la info de la tienda (cifrada)."""
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

    # --- CAMPOS DE TIENDA ---
    tk.Label(frame, text="Marca:").grid(row=5, column=0, sticky="w", pady=2)
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

        if pymssql is None:
            messagebox.showerror(
                "Dependencia faltante",
                "No se encontró el módulo 'pymssql'. Instálalo antes de continuar (pip install pymssql)."
            )
            return

        config = configparser.ConfigParser()
        config['Database'] = {
            'Server': server,
            'Database': database,
            'UID': user,
            'PWD': password  # en claro en memoria; se cifra al guardar
        }
        config['StoreInfo'] = {
            'Marca': marca,
            'Pais': pais,
            'TipoTienda': tipo_tienda
        }

        try:
            ok, err = _test_db_connection(server, database, user, password, timeout=10)
            if not ok:
                messagebox.showerror(
                    "No se pudo conectar",
                    "No se guardó la configuración porque la conexión a la base de datos falló:\n\n"
                    f"{err}"
                )
                return

            _write_config_encrypted(config, scope="user")
            messagebox.showinfo(
                "Éxito",
                "Conexión verificada y configuración guardada.\nReinicie la aplicación para comenzar la sincronización."
            )
            root.destroy()

        except Exception as e:
            logger.exception("Error al guardar configuración cifrada")
            messagebox.showerror(
                "Error al guardar",
                f"No se pudo completar el guardado de la configuración cifrada:\n{e}"
            )

    save_button = tk.Button(frame, text="Guardar Configuración", command=save_settings, width=30)
    save_button.grid(row=8, columnspan=2, pady=20)

    root.mainloop()


# --- LÓGICA DE CONEXIÓN (pymssql) ---
def _test_db_connection(server: str, database: str, uid: str, pwd: str, timeout: int = 10):
    """Intenta conectar vía pymssql; devuelve (True, None) o (False, 'error')."""
    if pymssql is None:
        return False, "No se encontró el módulo 'pymssql'."
    try:
        # Nota: soporta 'SERVER,PUERTO' o 'SERVER:PUERTO' en 'server'
        conn = pymssql.connect(server=server, user=uid, password=pwd, database=database,
                               login_timeout=timeout, timeout=timeout, charset='UTF-8')
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)

def get_connection_params_from_config():
    """Descifra config.enc y devuelve tupla (server, database, uid, pwd)."""
    try:
        cfg = _read_config_decrypted()
        db = cfg['Database']
        return db['Server'], db['Database'], db['UID'], db['PWD']
    except Exception as e:
        logger.error(f"Error al leer/descifrar la configuración de BD: {e}")
        return None

# --- LÓGICA DE LECTURA DE DATOS ---
def get_data_from_front(server: str, database: str, uid: str, pwd: str):
    """Se conecta a la BD, ejecuta la consulta y devuelve los resultados como lista de dicts. Incluye reintentos."""
    if pymssql is None:
        logger.error("No se encontró 'pymssql'. Abortando consulta.")
        return None

    sql_query = """
    ;WITH VentasAgregadas AS (
    SELECT
        ALM.NOMBREALMACEN AS Tienda,
        FV.CAJA,
        COUNT(DISTINCT FV.NUMSERIE + '-' + CAST(FV.NUMFACTURA AS VARCHAR)) AS NumeroFacturas,
        SUM(AL.TOTAL) AS ImporteFacturas
    FROM
        FACTURASVENTA FV
    INNER JOIN ALBVENTACAB AC ON FV.NUMSERIE = AC.NUMSERIEFAC AND FV.NUMFACTURA = AC.NUMFAC AND FV.N = AC.NFAC
    INNER JOIN ALBVENTALIN AL ON AC.NUMSERIE = AL.NUMSERIE AND AC.NUMALBARAN = AL.NUMALBARAN AND AC.N = AL.N
    INNER JOIN ALMACEN ALM ON AL.CODALMACEN = ALM.CODALMACEN
    WHERE
        CAST(FV.FECHA AS DATE) = CAST(GETDATE() AS DATE)
    GROUP BY
        ALM.NOMBREALMACEN, 
        FV.CAJA
),
ComprasAgregadas AS (
    SELECT
        ALM.NOMBREALMACEN AS Tienda,
        COUNT(DISTINCT ACC.NUMSERIE + '-' + CAST(ACC.NUMALBARAN AS VARCHAR)) AS NumeroCompras,
        SUM(ACL.TOTAL) AS ImporteCompras
    FROM
        ALBCOMPRACAB ACC
    INNER JOIN ALBCOMPRALIN ACL ON ACC.NUMSERIE = ACL.NUMSERIE AND ACC.NUMALBARAN = ACC.NUMALBARAN AND ACC.N = ACL.N
    INNER JOIN ALMACEN ALM ON ACL.CODALMACEN = ALM.CODALMACEN
    WHERE
        CAST(ACC.FECHAALBARAN AS DATE) = CAST(GETDATE() AS DATE)
    GROUP BY
        ALM.NOMBREALMACEN
),
Pendientes AS (
    SELECT
        RT.CAJA AS Caja,
        COUNT(RT.ID) AS TransaccionesPendientes
    FROM
        REM_TRANSACCIONES RT
    WHERE
        RT.IDCENTRAL = -1
    GROUP BY
        RT.CAJA
),
TransaccionesTotales AS (
    SELECT
        RT.CAJA AS Caja,
        COUNT(RT.ID) AS TransaccionesGenerales
    FROM
        REM_TRANSACCIONES RT
    GROUP BY
        RT.CAJA
),
MovimientosConsolidados AS (
    SELECT Tienda, Caja, NumeroFacturas, ImporteFacturas, 0 AS NumeroCompras, 0 AS ImporteCompras FROM VentasAgregadas
    UNION ALL
    SELECT Tienda, NULL AS Caja, 0 AS NumeroFacturas, 0 AS ImporteFacturas, NumeroCompras, ImporteCompras FROM ComprasAgregadas
)
SELECT
    MC.Tienda,
    MC.Caja,
    SUM(MC.NumeroFacturas) AS Numero_de_Facturas,
    SUM(MC.ImporteFacturas) AS Importe_Facturas,
    SUM(MC.NumeroCompras) AS Numero_de_Compras,
    SUM(MC.ImporteCompras) AS Importe_Compras,
    MAX(ISNULL(TT.TransaccionesGenerales, 0)) AS Transacciones_Totales,
    MAX(ISNULL(P.TransaccionesPendientes, 0)) AS Transacciones_Pendientes
FROM
    MovimientosConsolidados MC
LEFT JOIN
    Pendientes P ON MC.Caja = P.Caja
LEFT JOIN
    TransaccionesTotales TT ON MC.Caja = TT.Caja
GROUP BY
    MC.Tienda, 
    MC.Caja
ORDER BY
    MC.Tienda, 
    MC.Caja;
    """

    for attempt in range(1, 4):
        try:
            with pymssql.connect(server=server, user=uid, password=pwd, database=database,
                                 login_timeout=10, timeout=30, charset='UTF-8') as conn:
                with conn.cursor(as_dict=True) as cursor:
                    cursor.execute(sql_query)
                    rows = cursor.fetchall()  # lista de dicts
            logger.info(f"Se obtuvieron {len(rows)} registros (intento {attempt}).")
            app_state["last_sync"] = time.strftime('%d-%m-%Y %H:%M:%S')
            return rows
        except Exception as e:
            logger.warning(f"Error al conectar o consultar la BD (intento {attempt}/3): {e}")
            time.sleep(2 * attempt)

    logger.error("Falló la consulta tras 3 intentos.")
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

### NUEVO ###
def _send_data_to_api(payload: dict):
    """
    Autentica contra la API, obtiene un token y envía el payload al webhook.
    """
    login_url = "https://aplicaciones.grupodavid1.com/v1/api2/login"
    webhook_url = "https://aplicaciones.grupodavid1.com/v1/api/webhook"
    credentials = {
        "username": "AdminGD",
        "password": "F1r3Base.GdPa4ss"
    }
    
    token = None
    # --- 1. Autenticación para obtener token ---
    try:
        logger.info("Autenticando con la API...")
        # Hacemos la petición de login
        login_response = requests.post(login_url, json=credentials, timeout=15)
        login_response.raise_for_status()  # Lanza una excepción si la respuesta es un error (4xx o 5xx)
        
        # Asumimos que la API devuelve un JSON con una clave para el token.
        # ¡IMPORTANTE! Puede que necesites ajustar ".get('token')" si la clave se llama diferente (ej: "access_token").
        api_response_data = login_response.json()
        token = api_response_data.get("access_token") # O como se llame la clave del token        
        if not token:
            logger.error(f"No se recibió un token válido en la respuesta de la API de login. Respuesta: {api_response_data}")
            return False

        logger.info("Autenticación exitosa.")

    except requests.exceptions.RequestException as e:
        logger.error(f"Error durante la autenticación con la API: {e}")
        return False
    except json.JSONDecodeError:
        logger.error(f"La respuesta de la API de login no es un JSON válido: {login_response.text}")
        return False
        
    # --- 2. Envío de datos al Webhook con el token ---
    if not token:
        logger.error("No se puede continuar sin un token de autenticación.")
        return False

    try:
        logger.info(f"Enviando {len(payload.get('Registros', []))} registros al webhook...")
        
        # Asumimos que la autenticación es de tipo "Bearer". Esto es un estándar común.
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        webhook_response = requests.post(webhook_url, json=payload, headers=headers, timeout=30)
        webhook_response.raise_for_status()

        logger.info(f"Datos enviados exitosamente al webhook. Código de estado: {webhook_response.status_code}")
        return True

    except requests.exceptions.RequestException as e:
        logger.error(f"Error al enviar datos al webhook: {e}")
        # Si el servidor da una respuesta con error, la mostramos en el log para depurar.
        if e.response:
            logger.error(f"Detalle de la respuesta del servidor: {e.response.text}")
        return False

# --- LÓGICA DE JOB ---
def job(server: str, database: str, uid: str, pwd: str):
    """Tarea de trabajo que se ejecuta en cada ciclo."""
    logger.info("--- Iniciando ciclo de sincronización ---")

    store_info = get_store_info()
    datos_rescatados = get_data_from_front(server, database, uid, pwd)

    if datos_rescatados:
        if store_info:
            logger.info(f"Contexto: Marca={store_info['marca']}, País={store_info['pais']}, Tipo={store_info['tipo_tienda']}")
        else:
            logger.warning("No se pudo cargar la información de la tienda desde config.enc.")

        logger.info(f"-> Se encontraron {len(datos_rescatados)} registros.")
        
        try:
            payload = _build_json_payload(datos_rescatados, store_info)
            logger.info(f"JSON para endpoint: {json.dumps(payload, ensure_ascii=False)}")
            
            ### NUEVO: LLAMADA PARA ENVIAR DATOS A LA API ###
            success = _send_data_to_api(payload)
            if success:
                logger.info("El payload fue enviado correctamente a la API.")
            else:
                logger.error("Falló el envío del payload a la API. Revisa los logs anteriores para más detalles.")

        except Exception as e:
            logger.exception(f"Error inesperado construyendo o enviando el payload: {e}")
            
    elif datos_rescatados == []:
        logger.info("-> La consulta se ejecutó, pero no se encontraron registros para la fecha actual.")
    else:
        logger.warning("-> No se rescataron datos en este ciclo. Revisa logs de errores anteriores.")

    logger.info("--- Ciclo de sincronización finalizado ---")


# --- LÓGICA DE LA BANDEJA DEL SISTEMA ---
def create_image():
    """Crea una imagen genérica si icon.png no existe (desde RESOURCE_DIR)."""
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

def run_scheduler_thread(server: str, database: str, uid: str, pwd: str):
    """Hilo que ejecuta las tareas programadas sin busy-wait."""
    job_with_params = lambda: job(server, database, uid, pwd)

    # >>> NUEVO: programa usando el intervalo actual y una etiqueta
    schedule.clear('sync_job')
    schedule.every(app_state.get("interval_minutes", 15)).minutes.do(job_with_params).tag('sync_job')

    logger.info(f"Servicio de sincronización iniciado (intervalo {app_state['interval_minutes']} min). Primera ejecución inmediata.")
    job_with_params()

    while not app_state["stop_event"].wait(1):
        schedule.run_pending()
    logger.info("Hilo de scheduler detenido.")

def get_menu(server: str, database: str, uid: str, pwd: str):
    """Genera el menú dinámico para el icono de la bandeja."""
    def force_sync(icon_obj, menu_item):
        logger.info("Sincronización manual solicitada.")
        threading.Thread(target=job, args=(server, database, uid, pwd), daemon=True).start()

    def open_config(icon_obj, menu_item):
        logger.info("Apertura de configuración solicitada.")
        threading.Thread(target=lambda: _require_admin_key_then(launch_config_gui), daemon=True).start()

    # >>> NUEVO: cambiar intervalo en caliente (con diálogo)
    def change_interval(icon_obj, menu_item):
        try:
            root = tk.Tk(); root.withdraw()
            val = simpledialog.askinteger(
                "Intervalo de ejecución",
                "Minutos entre sincronizaciones (1-1440):",
                minvalue=1, maxvalue=1440, parent=root
            )
        finally:
            try: root.destroy()
            except Exception: pass

        if val is None:
            return  # cancelado

        app_state["interval_minutes"] = int(val)
        # Reprograma el job etiquetado
        schedule.clear('sync_job')
        job_with_params = lambda: job(server, database, uid, pwd)
        schedule.every(app_state["interval_minutes"]).minutes.do(job_with_params).tag('sync_job')
        _set_config_interval(app_state["interval_minutes"])
        logger.info(f"Intervalo de sincronización actualizado a {app_state['interval_minutes']} min.")

    def _exit(icon_obj, menu_item):
        exit_app(icon_obj, menu_item)

    # --- Items de menú ---
    yield item(lambda i: f'Última Sincronización: {app_state["last_sync"]}', None, enabled=False)
    # >>> NUEVO: mostrar el intervalo actual
    yield item(lambda i: f'Intervalo actual: {app_state["interval_minutes"]} min', None, enabled=False)
    yield Menu.SEPARATOR
    yield item('Sincronizar Ahora', force_sync)
    yield item('Configurar...', open_config)
    # >>> NUEVO: opción para cambiar el intervalo
    yield item('Cambiar intervalo…', change_interval)
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

    # Validaciones de dependencias
    if sys.platform != 'win32' or win32crypt is None:
        # Podemos dejar arrancar la GUI para informar, pero no continuar sin DPAPI
        msg = "Esta aplicación requiere Windows y el paquete 'pywin32' para cifrado DPAPI."
        logger.error(msg)
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Requisito no cumplido", msg)
            root.destroy()
        except Exception:
            pass
        sys.exit(1)

    if pymssql is None:
        msg = "Dependencia faltante: instale 'pymssql' (pip install pymssql) para conectar a SQL Server sin ODBC."
        logger.error(msg)
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Dependencia faltante", msg)
            root.destroy()
        except Exception:
            pass
        sys.exit(1)

    if not os.path.exists(CONFIG_FILE_ENC):
        logger.warning(f"No se encontró '{CONFIG_FILE_ENC}'. Iniciando GUI de configuración.")
        try:
            launch_config_gui()
            logger.info("Configuración no encontrada. El programa se cerrará.")
            sys.exit("Configuración guardada. Por favor, reinicie la aplicación.")
        except Exception as e:
            logger.error(f"No se pudo abrir la GUI de configuración: {e}")
            sys.exit(1)

    logger.info(f"Archivo de configuración cifrado '{CONFIG_FILE_ENC}' encontrado. Iniciando servicio.")
    params = get_connection_params_from_config()

    if params:
        server, database, uid, pwd = params

        app_state["interval_minutes"] = _get_config_interval(default=15)

        image = create_image()
        tray_icon = icon(
            'SyncICGFront',
            image,
            'Sincronizador ICG Front',
            menu=Menu(lambda: get_menu(server, database, uid, pwd))
        )
        app_state['tray_icon'] = tray_icon

        scheduler_thread = threading.Thread(target=run_scheduler_thread, args=(server, database, uid, pwd), daemon=True)
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

    if not os.path.exists(CONFIG_FILE_ENC):
        logger.warning(f"No se encontró '{CONFIG_FILE_ENC}'. Iniciando bootstrap de clave y GUI de configuración.")
        # Si no existe clave, crearla primero
        if not os.path.exists(CONFIG_KEY_FILE):
            created = _bootstrap_admin_key_ui()
            if not created:
                sys.exit("No se creó la clave de administración. Saliendo.")
        try:
            launch_config_gui()
            logger.info("Configuración no encontrada. El programa se cerrará.")
            sys.exit("Configuración guardada. Por favor, reinicie la aplicación.")
        except Exception as e:
            logger.error(f"No se pudo abrir la GUI de configuración: {e}")
            sys.exit(1)

    else:
        logger.error("No se pudo iniciar. El archivo de configuración es inválido o no se pudo descifrar.")
        try:
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("Error de Configuración",
                                 "No se pudo iniciar. 'config.enc' es inválido o no se pudo descifrar.\n"
                                 "Borre el archivo para reconfigurar.")
            root.destroy()
        except Exception:
            pass
        sys.exit("Error en la configuración.")