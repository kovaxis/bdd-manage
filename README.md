# bdd-manage - Setup y manejo del servidor de IIC2513 Bases de Datos

Este repositorio contiene dos herramientas útiles para el manejo de el servidor de Bases de Datos: `setup.sh` y `userctl`.

## `setup.sh`

Instalar todo el software necesario para dejar funcionando el servidor.
Requiere permisos de _root_, y toma como argumento el nombre de usuario del usuario que actuará como administrador.
Instala la herramienta `userctl`, para poder agregar y manejar usuarios.

**NOTA**: Este script no inicializa los usuarios, para eso es necesario ejecutar `userctl create`, como indica la sección a continuación.

## `userctl`

Para agregar, quitar, escanear y en general manejar a los usuarios.

Se pueden ver todos los comandos y argumentos usando `userctl --help`.

### Comandos notables

- `userctl create --list <lista.csv>`: Agrega usuarios a partir de la lista entregada. La lista ha de tener una columna `id` y una columna `password`.
- `userctl run --command 'printf "{password}\n{password}\n" | passwd {id}'`: Reiniciar todas las contraseñas a sus valores originales.
