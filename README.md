# bdd-manage - Setup y manejo del servidor de IIC2513 Bases de Datos

Este repositorio contiene dos herramientas útiles para el manejo de el servidor de Bases de Datos: `setup.sh` y `userctl`.

## `setup.sh`

Instalar todo el software necesario para dejar funcionando el servidor.
Toma como argumento el nombre del usuario que actuará como administrador.
Instala la herramienta `userctl`, para poder agregar y manejar usuarios.

El script es idempotente, esto significa que correrlo múltiples veces no genera nuevos cambios.

**NOTA**: Este script no inicializa los usuarios, para eso es necesario ejecutar `userctl create`, como indica la sección a continuación.

## `userctl`

Para agregar, quitar, escanear y en general manejar a los usuarios.

Se pueden ver todos los comandos y argumentos usando `userctl --help`.

### Comandos notables

- `userctl create --list <lista.csv>`: Agrega usuarios a partir de la lista entregada. La lista ha de tener una columna `id`/`email` y una columna `password`.
- `userctl scan --out reporte.csv`: Generar un reporte sobre la última modificación que ha hecho cada usuario.
- `userctl run` seguido de `[ {id} = usuario ] && printf "{password}\n{password}\n" | sudo passwd {id} && sudo passwd -e {id}`: Restablecer una contraseña particular a su valor original.
- `userctl run` seguido de `sudo passwd -e {id} && sudo -u postgres psql -c 'ALTER ROLE "{id}" WITH PASSWORD null;'`: Forzar a los usuarios a elegir sus contraseñas.
