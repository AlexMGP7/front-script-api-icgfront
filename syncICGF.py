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
# Usamos un diccionario para mantener el estado que será accedido por diferentes hilos.
app_state = {
    "last_sync": "Nunca",
    "stop_event": threading.Event()
}

# --- CONFIGURACIÓN GLOBAL ---

# Determina el directorio base, ya sea en modo script o .exe compilado
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(BASE_DIR, 'config.ini')
LOG_FILE = os.path.join(BASE_DIR, "icg_front_sync.log")
ICON_FILE = os.path.join(BASE_DIR, 'icon.png')

# --- CONFIGURACIÓN DE LOGGING (Sin cambios) ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(LOG_FILE, mode='a', maxBytes=1*1024*1024,
                                  backupCount=5, encoding='utf-8', delay=0)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger('root')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)


# --- INTERFAZ GRÁFICA DE CONFIGURACIÓN (Sin cambios) ---
def launch_config_gui():
    """Crea y muestra una ventana para guardar las credenciales."""
    root = tk.Tk()
    root.title("Configuración de Conexión a BD")
    root.withdraw()
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_reqwidth()) / 2
    y = (root.winfo_screenheight() - root.winfo_reqheight()) / 2
    root.geometry(f"+{int(x)}+{int(y)}")
    root.deiconify()

    def save_credentials():
        server = entry_server.get()
        database = entry_database.get()
        user = entry_user.get()
        password = entry_password.get()

        if not all([server, database, user, password]):
            messagebox.showerror("Error", "Todos los campos son obligatorios.")
            return

        config = configparser.ConfigParser()
        config['Database'] = {
            'Server': server,
            'Database': database,
            'UID': user,
            'PWD_b64': base64.b64encode(password.encode('utf-8')).decode('utf-8')
        }

        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            messagebox.showinfo("Éxito", "Credenciales guardadas. Reinicie la aplicación para comenzar la sincronización.")
            root.destroy()
        except Exception as e:
            messagebox.showerror("Error al guardar", f"No se pudo escribir el archivo de configuración:\n{e}")

    frame = tk.Frame(root, padx=15, pady=15)
    frame.pack(padx=10, pady=10)

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

    save_button = tk.Button(frame, text="Guardar", command=save_credentials, width=25)
    save_button.grid(row=4, columnspan=2, pady=20)

    root.mainloop()


# --- LÓGICA DE SINCRONIZACIÓN (Modificada para actualizar estado) ---
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
        logger.error(f"Error al leer la configuración: {e}")
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
        # Actualizamos el estado con la hora de la sincronización exitosa
        app_state["last_sync"] = time.strftime('%d-%m-%Y %H:%M:%S')
        return datos_nuevos
    except Exception as e:
        logger.error(f"Error al conectar o consultar la BD: {e}")
        return None

def job(connection_string):
    """Tarea de trabajo que se ejecuta en cada ciclo."""
    logger.info("--- Iniciando ciclo de sincronización ---")
    
    # Esta función ya actualiza app_state["last_sync"] si tiene éxito
    datos_rescatados = get_data_from_front(connection_string)

    # Si la sincronización tuvo éxito (no devolvió None), actualizamos la UI
    if datos_rescatados is not None:
        # Buscamos el ícono en el estado de la app y actualizamos su menú
        if 'tray_icon' in app_state and app_state['tray_icon']:
            app_state['tray_icon'].update_menu()

    # --- El resto de tu lógica de logging permanece igual ---
    if datos_rescatados:
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
        return Image.open(ICON_FILE)
    else:
        # Crea una imagen en blanco 64x64
        width = 64
        height = 64
        image = Image.new('RGB', (width, height), color = 'darkgrey')
        dc = ImageDraw.Draw(image)
        # Dibuja una 'S' de 'Sync' en el centro
        dc.text((20, 15), "S", fill="white", font_size=32)
        return image

def run_scheduler_thread(connection_string):
    """Hilo que ejecuta las tareas programadas."""
    job_with_conn = lambda: job(connection_string)
    
    schedule.every(15).minutes.do(job_with_conn)
    
    # Ejecuta una vez al inicio de forma explícita
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
    app_state["stop_event"].set() # Señal para detener el hilo del scheduler
    tray_icon.stop() # Detiene el icono de la bandeja
    logger.info("Aplicación cerrada.")

# --- PUNTO DE ENTRADA PRINCIPAL ---
# --- PUNTO DE ENTRADA PRINCIPAL ---
if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"No se encontró '{CONFIG_FILE}'. Iniciando GUI de configuración.")
        launch_config_gui()
        logger.info("Configuración no encontrada. El programa se cerrará.")
        sys.exit("Configuración guardada. Por favor, reinicie la aplicación.")

    logger.info(f"Archivo de configuración '{CONFIG_FILE}' encontrado. Iniciando servicio.")
    conn_str = get_connection_string()
    
    if conn_str:
        # AÑADIMOS EL ÍCONO AL ESTADO INICIAL
        app_state['tray_icon'] = None 

        # 1. Creamos el objeto del ícono primero
        image = create_image()
        tray_icon = icon(
            'SyncICGFront',
            image,
            'Sincronizador ICG Front',
            menu=Menu(lambda: get_menu(conn_str))
        )
        tray_icon.exit_app = lambda: exit_app(tray_icon)

        # 2. Guardamos la referencia al ícono en el estado global
        app_state['tray_icon'] = tray_icon

        # 3. AHORA SÍ, iniciamos el hilo del planificador en segundo plano
        #    Será un hilo "demonio" para que se cierre si el hilo principal termina.
        scheduler_thread = threading.Thread(target=run_scheduler_thread, args=(conn_str,), daemon=True)
        scheduler_thread.start()
        
        # 4. Finalmente, ejecutamos el ícono (esto bloquea el hilo principal)
        tray_icon.run()

    else:
        logger.error("No se pudo iniciar. El archivo de configuración es inválido.")
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error de Configuración", "No se pudo iniciar. 'config.ini' es inválido. Bórrelo para reconfigurar.")
        root.destroy()
        sys.exit("Error en la configuración.")