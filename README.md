# Sincronizador ICG Front a API (SyncICGFront)

 

**SyncICGFront** es una aplicación de escritorio para Windows que se ejecuta en segundo plano para extraer datos transaccionales del sistema de punto de venta ICG Front y enviarlos de forma segura a una API web centralizada.

La aplicación está diseñada para ser desatendida, robusta y segura, funcionando como un servicio en la bandeja del sistema (`system tray`) sin requerir interacción del usuario una vez configurada.

-----

## Características Principales

  * **Sincronización Automática:** Se ejecuta de forma periódica y programable (configurable por el usuario) para enviar los datos del día.
  * **Ejecución en Segundo Plano:** Opera discretamente desde la bandeja del sistema, mostrando el estado de la última sincronización y permitiendo acciones rápidas.
  * **Configuración Segura:** Las credenciales de la base de datos y la configuración de la tienda se almacenan de forma cifrada utilizando la DPAPI nativa de Windows, vinculada a la cuenta de usuario.
  * **Sin Dependencias de ODBC:** Utiliza el driver `pymssql` para conectarse directamente a SQL Server, eliminando la necesidad de configurar DSN en cada equipo.
  * **Interfaz Gráfica de Configuración:** Incluye una GUI intuitiva para la configuración inicial de la base de datos y los datos de la tienda, protegida por una clave de administrador.
  * **Envío de Datos a API REST:** Construye un payload JSON con los datos agregados de ventas y compras y lo envía a un webhook, manejando la autenticación por token.
  * **Registro de Actividad (Logging):** Guarda un registro detallado de cada ciclo de sincronización y de posibles errores en un archivo `icg_front_sync.log`.

## ¿Cómo Funciona?

1.  **Extracción de Datos:** La aplicación se conecta a la base de datos de ICG Front y ejecuta una consulta SQL para obtener un resumen de las transacciones del día actual. Esto incluye:

      * Número e importe de facturas de venta.
      * Número e importe de compras.
      * Total de transacciones y transacciones pendientes de sincronizar.

2.  **Enriquecimiento de Datos:** La información extraída se enriquece con los datos de la tienda (Marca, País, Tipo) guardados en la configuración local.

3.  **Autenticación y Envío:**

      * La aplicación primero solicita un token de autenticación a la API de `grupodavid1.com`.
      * Con el token obtenido, envía el payload JSON completo al endpoint del webhook.

4.  **Ciclo de Repetición:** Este proceso se repite automáticamente cada `X` minutos (15 por defecto, pero configurable desde el menú de la aplicación).

## Configuración

Al ejecutar la aplicación por primera vez, se solicitará crear una **clave de administración**. Esta clave se usará en el futuro para proteger el acceso a la ventana de configuración.

Posteriormente, se abrirá una ventana para configurar los siguientes parámetros:

  * **Datos de la Base de Datos:**
      * Servidor (IP o Nombre)
      * Nombre de la Base de Datos
      * Usuario de SQL
      * Contraseña
  * **Información de la Tienda:**
      * Marca
      * País (PAN, COL, etc.)
      * Tipo de Tienda (Retail, Ecommerce)

La aplicación no guardará la configuración hasta que no pueda verificar exitosamente la conexión con la base de datos. Una vez guardada, la aplicación debe reiniciarse para comenzar a sincronizar.

## Despliegue y Actualizaciones

Esta aplicación está gestionada por un **actualizador universal**. Las nuevas versiones se publican automáticamente en la sección de [Releases](https://www.google.com/search?q=https://github.com/alexmgp7/icg-front-sync/releases) de este repositorio. El actualizador en cada PC se encargará de descargar e instalar la última versión disponible sin intervención manual.

-----

## Cómo Contribuir y Lanzar una Nueva Versión

Este proyecto utiliza **GitHub Actions** para automatizar completamente el proceso de compilación y publicación de nuevas versiones. El flujo de trabajo se activa al crear y empujar una nueva etiqueta (tag) que comience con `v`.

Sigue estos pasos para lanzar una nueva versión:

1.  **Finaliza tus Cambios:** Asegúrate de que todos los cambios de código estén terminados, probados y subidos a la rama principal (`main` o `master`).

2.  **Crea una Etiqueta (Tag) de Versión:** Desde tu terminal local, crea una nueva etiqueta de Git siguiendo el formato de versionado semántico (vMAJOR.MINOR.PATCH).

    ```bash
    # Ejemplo para una nueva versión menor
    git tag v1.1.0
    ```

3.  **Sube la Etiqueta a GitHub:** El `push` de una etiqueta es un comando separado. Este es el paso que activará la automatización.

    ```bash
    git push origin v1.1.0
    ```

4.  **¡Eso es todo\!** Al recibir la nueva etiqueta, GitHub Actions ejecutará automáticamente el flujo de trabajo definido en `.github/workflows/build-release.yml`:

      * Creará una máquina virtual con Windows.
      * Instalará Python y todas las dependencias del proyecto.
      * Compilará el script `syncICGF.py` en un único archivo `SyncICGFront.exe` usando PyInstaller.
      * Creará un nuevo **Release** en GitHub con el nombre de la etiqueta (`v1.1.0`).
      * Adjuntará el `SyncICGFront.exe` recién compilado como un archivo a ese *release*.

Una vez que la acción termine (puedes ver el progreso en la pestaña "Actions" de tu repositorio), el `updater.exe` en las PCs de los clientes detectará y descargará esta nueva versión en su próximo ciclo de revisión.