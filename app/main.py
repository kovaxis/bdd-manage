#!/usr/bin/env python3

# Script para crear, destruir y en general manejar usuarios.
# Correr el comando con el argumento `--help` para ver la descripcion y posibles comandos.

from typer import Typer
import sys
import os
from app.io import read_system_users
from app.scan import app as scan_app
from app.sync import app as sync_app
from app.run import app as run_app
from app.report import app as report_app
from app.canvas import app as canvas_app
from app.subrun import app as subrun_app


app = Typer()

app.add_typer(subrun_app)
app.add_typer(sync_app)
app.add_typer(run_app)
app.add_typer(scan_app)
app.add_typer(report_app)
app.add_typer(canvas_app, name="canvas")


@app.command(
    "status",
)
def show_status():
    "Imprimir los usuarios del sistema."

    def show(msg: str, a: set[str]):
        print(f"{len(a)} {msg}: {' '.join(sorted(a))}")

    system = set(read_system_users().by_id.keys())
    show("usuarios en el sistema", system)


if __name__ == "__main__":
    print("argv:", sys.argv)
    if os.geteuid() == 0 and os.getenv("ALLOW_ROOT") != "true":
        print("userctl should not run as root")
        sys.exit(1)
    og_pwd = os.getenv("ORIGINAL_PWD")
    if og_pwd is not None:
        os.chdir(og_pwd)
    try:
        app()
    except InterruptedError:
        sys.exit(1)
