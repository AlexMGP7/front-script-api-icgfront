import tkinter as tk
from tkinter import messagebox
import configparser
import base64
import os
import sys
import pyodbc
import schedule
import time
import logging
from logging.handlers import RotatingFileHandler
import threading
from pystray import MenuItem as item, Icon as icon, Menu
from PIL import Image, ImageDraw

# --- ESTADO GLOBAL DE LA APLICACIÓN ---
app_state = {
    "last_sync": "Nunca",
    "stop_event": threading.Event()
}

# --- CONFIGURACIÓN GLOBAL ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')
LOG_FILE = os.path.join(BASE_DIR, "icg_front_sync.log")
ICON_FILE = os.path.join(BASE_DIR, 'icon.png')

# --- CONFIGURACIÓN DE LOGGING ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(LOG_FILE, mode='a', maxBytes=1*1024*1024,
                                  backupCount=5, encoding='utf-8', delay=0)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger('root')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)


# --- INTERFAZ GRÁFICA DE CONFIGURACIÓN (MODIFICADA) ---
def launch_config_gui():
    """Crea y muestra una ventana para guardar las credenciales y la info de la tienda."""
    root = tk.Tk()
    root.title("Configuración de Conexión y Tienda")
    root.withdraw()
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_reqwidth()) / 2
    y = (root.winfo_screenheight() - root.winfo_reqheight()) / 2
    root.geometry(f"+{int(x)}+{int(y)}")
    root.deiconify()

    def save_settings():
        # Datos de la base de datos
        server = entry_server.get()
        database = entry_database.get()
        user = entry_user.get()
        password = entry_password.get()
        
        # Nuevos datos de la tienda
        marca = entry_marca.get()
        pais = entry_pais.get()
        tipo_tienda = entry_tipo.get()

        if not all([server, database, user, password, marca, pais, tipo_tienda]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        config = configparser.ConfigParser()
        config['Database'] = {
            'Server': server,
            'Database': database,
            'UID': user,
            'PWD_b64': base64.b64encode(password.encode('utf-8')).decode('utf-8')
        }
        # Nueva sección para la información de la tienda
        config['StoreInfo'] = {
            'Marca': marca,
            'Pais': pais,
            'TipoTienda': tipo_tienda
        }

        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            messagebox.showinfo("Éxito", "Configuración guardada. Reinicie la aplicación para comenzar la sincronización.")
            root.destroy()
        except Exception as e:
            messagebox.showerror("Error al guardar", f"No se pudo escribir el archivo de configuración:\n{e}")

    frame = tk.Frame(root, padx=15, pady=15)
    frame.pack(padx=10, pady=10)

    # --- Campos de BD ---
    tk.Label(frame, text="Servidor (IP o Nombre):").grid(row=0, column=0, sticky="w", pady=2)
    entry_server = tk.Entry(frame, width=40)
    entry_server.grid(row=0, column=1, pady=2)

    tk.Label(frame, text="Nombre Base de Datos:").grid(row=1, column=0, sticky="w", pady=2)
    entry_database = tk.Entry(frame, width=40)
    entry_database.grid(row=1, column=1, pady=2)

    tk.Label(frame, text="Usuario:").grid(row=2, column=0, sticky="w", pady=2)
    entry_user = tk.Entry(frame, width=40)
    entry_user.grid(row=2, column=1, pady=2)

    tk.Label(frame, text="Contraseña:").grid(row=3, column=0, sticky="w", pady=2)
    entry_password = tk.Entry(frame, width=40, show="*")
    entry_password.grid(row=3, column=1, pady=2)
    
    # Separador visual
    tk.Frame(frame, height=2, bg="grey").grid(row=4, columnspan=2, pady=10, sticky="ew")

    # --- NUEVOS CAMPOS DE TIENDA ---
    tk.Label(frame, text="Marca (BBW/VS/LCW):").grid(row=5, column=0, sticky="w", pady=2)
    entry_marca = tk.Entry(frame, width=40)
    entry_marca.grid(row=5, column=1, pady=2)
    
    tk.Label(frame, text="País (PAN/COL/etc.):").grid(row=6, column=0, sticky="w", pady=2)
    entry_pais = tk.Entry(frame, width=40)
    entry_pais.grid(row=6, column=1, pady=2)

    tk.Label(frame, text="Tipo Tienda (Retail/Ecommerce):").grid(row=7, column=0, sticky="w", pady=2)
    entry_tipo = tk.Entry(frame, width=40)
    entry_tipo.grid(row=7, column=1, pady=2)

    save_button = tk.Button(frame, text="Guardar Configuración", command=save_settings, width=30)
    save_button.grid(row=8, columnspan=2, pady=20)

    root.mainloop()

# --- LÓGICA DE SINCRONIZACIÓN ---

def get_connection_string():
    """Lee el archivo config.ini y construye la cadena de conexión."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    try:
        db_config = config['Database']
        server, database, uid = db_config['Server'], db_config['Database'], db_config['UID']
        pwd_decoded = base64.b64decode(db_config['PWD_b64']).decode('utf-8')
        return f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server};DATABASE={database};UID={uid};PWD={pwd_decoded}"
    except Exception as e:
        logger.error(f"Error al leer la configuración de BD: {e}")
        return None

# --- NUEVA FUNCIÓN ---
def get_store_info():
    """Lee la información de la tienda desde el config.ini."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    try:
        store_config = config['StoreInfo']
        return {
            'marca': store_config['Marca'],
            'pais': store_config['Pais'],
            'tipo_tienda': store_config['TipoTienda']
        }
    except KeyError as e:
        logger.error(f"Error al leer la configuración de la tienda: falta la clave {e} en config.ini")
        return None

def get_data_from_front(connection_string):
    """Se conecta a la BD, ejecuta la consulta y devuelve los resultados."""
    if not connection_string:
        logger.error("No se pudo obtener la cadena de conexión. Abortando consulta.")
        return None
    
    sql_query = """
    WITH VentasAgregadas AS (
        SELECT ALM.NOMBREALMACEN AS Tienda, FV.CAJA, COUNT(DISTINCT FV.NUMSERIE + '-' + CAST(FV.NUMFACTURA AS VARCHAR)) AS NumeroFacturas, SUM(AL.TOTAL) AS ImporteFacturas
        FROM FACTURASVENTA FV INNER JOIN ALBVENTACAB AC ON FV.NUMSERIE = AC.NUMSERIEFAC AND FV.NUMFACTURA = AC.NUMFAC AND FV.N = AC.NFAC INNER JOIN ALBVENTALIN AL ON AC.NUMSERIE = AL.NUMSERIE AND AC.NUMALBARAN = AL.NUMALBARAN AND AC.N = AL.N INNER JOIN ALMACEN ALM ON AL.CODALMACEN = ALM.CODALMACEN
        WHERE CAST(FV.FECHA AS DATE) = CAST(GETDATE() AS DATE) GROUP BY ALM.NOMBREALMACEN, FV.CAJA
    ), ComprasAgregadas AS (
        SELECT ALM.NOMBREALMACEN AS Tienda, COUNT(DISTINCT ACC.NUMSERIE + '-' + CAST(ACC.NUMALBARAN AS VARCHAR)) AS NumeroCompras, SUM(ACL.TOTAL) AS ImporteCompras
        FROM ALBCOMPRACAB ACC INNER JOIN ALBCOMPRALIN ACL ON ACC.NUMSERIE = ACL.NUMSERIE AND ACC.NUMALBARAN = ACL.NUMALBARAN AND ACC.N = ACL.N INNER JOIN ALMACEN ALM ON ACL.CODALMACEN = ALM.CODALMACEN
        WHERE CAST(ACC.FECHAALBARAN AS DATE) = CAST(GETDATE() AS DATE) GROUP BY ALM.NOMBREALMACEN
    ), Pendientes AS (
        SELECT RT.CAJA AS Caja, COUNT(RT.ID) AS TransaccionesPendientes FROM REM_TRANSACCIONES RT WHERE RT.IDCENTRAL = -1 GROUP BY RT.CAJA
    ), TransaccionesTotales AS (
        SELECT RT.CAJA AS Caja, COUNT(RT.ID) AS TransaccionesGenerales FROM REM_TRANSACCIONES RT GROUP BY RT.CAJA
    ), MovimientosConsolidados AS (
        SELECT Tienda, Caja, NumeroFacturas, ImporteFacturas, 0 AS NumeroCompras, 0 AS ImporteCompras FROM VentasAgregadas
        UNION ALL SELECT Tienda, NULL AS Caja, 0 AS NumeroFacturas, 0 AS ImporteFacturas, NumeroCompras, ImporteCompras FROM ComprasAgregadas
    )
    SELECT MC.Tienda, MC.Caja, SUM(MC.NumeroFacturas) AS Numero_de_Facturas, SUM(MC.ImporteFacturas) AS Importe_Facturas, SUM(MC.NumeroCompras) AS Numero_de_Compras, SUM(MC.ImporteCompras) AS Importe_Compras, MAX(ISNULL(TT.TransaccionesGenerales, 0)) AS Transacciones_Totales, MAX(ISNULL(P.TransaccionesPendientes, 0)) AS Transacciones_Pendientes
    FROM MovimientosConsolidados MC LEFT JOIN Pendientes P ON MC.Caja = P.Caja LEFT JOIN TransaccionesTotales TT ON MC.Caja = TT.Caja
    GROUP BY MC.Tienda, MC.Caja ORDER BY MC.Tienda, MC.Caja;
    """
    try:
        with pyodbc.connect(connection_string, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute(sql_query)
            columnas = [column[0] for column in cursor.description]
            datos_nuevos = [dict(zip(columnas, fila)) for fila in cursor.fetchall()]
        logger.info(f"Se obtuvieron {len(datos_nuevos)} registros de la consulta.")
        app_state["last_sync"] = time.strftime('%d-%m-%Y %H:%M:%S')
        return datos_nuevos
    except Exception as e:
        logger.error(f"Error al conectar o consultar la BD: {e}")
        return None

# --- LÓGICA DE JOB (MODIFICADA) ---
def job(connection_string):
    """Tarea de trabajo que se ejecuta en cada ciclo."""
    logger.info("--- Iniciando ciclo de sincronización ---")
    
    store_info = get_store_info()
    datos_rescatados = get_data_from_front(connection_string)

    if datos_rescatados is not None:
        if 'tray_icon' in app_state and app_state['tray_icon']:
            app_state['tray_icon'].update_menu()

    if datos_rescatados:
        # LOG DE LA INFORMACIÓN DE LA TIENDA
        if store_info:
            logger.info(f"Contexto: Marca={store_info['marca']}, País={store_info['pais']}, Tipo={store_info['tipo_tienda']}")
        else:
            logger.warning("No se pudo cargar la información de la tienda desde config.ini.")
        
        # LOG DE LOS DATOS DE LA CONSULTA
        logger.info(f"-> Se encontraron {len(datos_rescatados)} registros. Mostrando detalle:")
        for registro in datos_rescatados:
            logger.info(f"    {registro}")
        logger.info("--- Fin del detalle de datos ---")
    elif datos_rescatados == []:
        logger.info("-> La consulta se ejecutó, pero no se encontraron registros para la fecha actual.")
    else:
        logger.warning("-> No se rescataron datos en este ciclo. Revisa logs de errores anteriores.")

    logger.info("--- Ciclo de sincronización finalizado ---")

# --- LÓGICA DE LA BANDEJA DEL SISTEMA (Sin cambios) ---
def create_image():
    """Crea una imagen genérica si icon.png no existe."""
    if os.path.exists(ICON_FILE):
        return Image.open(ICON_FILE)
    else:
        width = 64
        height = 64
        image = Image.new('RGB', (width, height), color = 'darkgrey')
        dc = ImageDraw.Draw(image)
        dc.text((20, 15), "S", fill="white", font_size=32)
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
    def force_sync():
        logger.info("Sincronización manual solicitada.")
        threading.Thread(target=job, args=(connection_string,)).start()

    yield item(
        lambda text: f'Última Sincronización: {app_state["last_sync"]}',
        None, enabled=False
    )
    yield Menu.SEPARATOR
    yield item('Sincronizar Ahora', force_sync)
    yield item('Salir', exit_app)
    
def exit_app(tray_icon):
    """Detiene los hilos y cierra la aplicación."""
    logger.info("Solicitud de salida recibida.")
    app_state["stop_event"].set()
    tray_icon.stop()
    logger.info("Aplicación cerrada.")

# --- PUNTO DE ENTRADA PRINCIPAL (Sin cambios) ---
if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"No se encontró '{CONFIG_FILE}'. Iniciando GUI de configuración.")
        launch_config_gui()
        logger.info("Configuración no encontrada. El programa se cerrará.")
        sys.exit("Configuración guardada. Por favor, reinicie la aplicación.")

    logger.info(f"Archivo de configuración '{CONFIG_FILE}' encontrado. Iniciando servicio.")
    conn_str = get_connection_string()
    
    if conn_str:
        app_state['tray_icon'] = None 

        image = create_image()
        tray_icon = icon(
            'SyncICGFront',
            image,
            'Sincronizador ICG Front',
            menu=Menu(lambda: get_menu(conn_str))
        )
        tray_icon.exit_app = lambda: exit_app(tray_icon)

        app_state['tray_icon'] = tray_icon

        scheduler_thread = threading.Thread(target=run_scheduler_thread, args=(conn_str,), daemon=True)
        scheduler_thread.start()
        
        tray_icon.run()

    else:
        logger.error("No se pudo iniciar. El archivo de configuración es inválido.")
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error de Configuración", "No se pudo iniciar. 'config.ini' es inválido. Bórrelo para reconfigurar.")
        root.destroy()
        sys.exit("Error en la configuración.")