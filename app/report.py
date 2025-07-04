import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import gzip
from pathlib import Path
import re
import traceback
from typing import Annotated
from zoneinfo import ZoneInfo
from pydantic import BaseModel, ValidationError
from typer import Argument, Option, Typer

from app.scan import FsInfo
from app.sync import sync_state
from app.types import DEFAULT_SCANS_PATH, Scan
from app.util import UserBundle, exception_context, find_users_in_group

app = Typer()


@dataclass
class FileItem:
    path: Path
    change: datetime
    is_dir: bool
    fsinfo: FsInfo


class ReportMode(str, Enum):
    all = "all"
    daily = "daily"
    latest = "latest"


@dataclass
class ReportCtx:
    revscandb: list[Scan]
    cachedscans: dict[int, dict[str, dict[Path, FileItem] | None]]
    subdir: Path
    ignore_hidden: bool
    use_ctime: bool
    check_prev_scans: bool
    ignore_dirs: bool
    regex: re.Pattern[str] | None
    report_mode: ReportMode
    timezone: ZoneInfo

    def subflatten(
        self,
        out: dict[Path, FileItem],
        path: Path,
        fsinfo: FsInfo,
        homein: tuple[str, ...],
    ):
        is_dir = isinstance(fsinfo.contents, list)
        if (
            len(homein) == 0  # Exclude files above `homein` path
            and not (
                self.ignore_dirs and is_dir
            )  # Exclude directories if ignoring them
            and (
                self.regex is None or self.regex.fullmatch(str(path))
            )  # If regex is present, include only if it matches
        ):
            # Include this file/directory in the scan
            out[path] = FileItem(
                path=path,
                change=datetime.fromtimestamp(
                    fsinfo.ctime if self.use_ctime else fsinfo.mtime,
                    tz=self.timezone,
                ),
                is_dir=is_dir,
                fsinfo=fsinfo,
            )
        if isinstance(fsinfo.contents, list):
            for child in fsinfo.contents:
                if self.ignore_hidden and child.name.startswith("."):
                    continue
                if len(homein) != 0 and homein[0] != child.name:
                    continue
                self.subflatten(out, path / child.name, child, homein[1:])

    def flatten(self, fsinfo: FsInfo) -> dict[Path, FileItem]:
        out: dict[Path, FileItem] = {}
        self.subflatten(out, Path("."), fsinfo, self.subdir.parts)
        return out

    def getscan(self, idx: int, user: str) -> dict[Path, FileItem] | None:
        if idx not in self.cachedscans:
            self.cachedscans[idx] = {}
        if user not in self.cachedscans[idx]:
            if user in self.revscandb[idx].users:
                userscan = self.revscandb[idx].users[user]
                self.cachedscans[idx][user] = self.flatten(userscan.home)
            else:
                self.cachedscans[idx][user] = None
        return self.cachedscans[idx][user]


class ScanReport(BaseModel):
    """
    Un reporte de usuario hecho a partir de varios escaneos.
    """

    usuario: str
    ultimos_cambios: str
    timestamp_escaneo: str
    tiene_archivo_php: str


def read_scandb(
    db_path: Path | None,
    min_time: datetime | None,
    max_time: datetime | None,
    tz: ZoneInfo,
) -> list[Scan]:
    db_path = db_path or DEFAULT_SCANS_PATH
    if not db_path.exists():
        print(f"warning: no scandb file found at {db_path}")
        return []

    scans: list[Scan] = []
    with exception_context(f"reading scan database from {db_path}"):
        with db_path.open("rb") as db_compressed_file:
            with gzip.open(db_compressed_file, "rb") as db_file:
                print(f"reading {db_path.stat().st_size / 1024}KB scan database")
                line = 0
                for scanline in db_file:
                    line += 1
                    try:
                        scan = Scan.model_validate_json(scanline)
                        scan.scantime = scan.scantime.astimezone(tz)
                        if (min_time is None or scan.scantime >= min_time) and (
                            max_time is None or scan.scantime <= max_time
                        ):
                            scans.append(scan)
                    except ValidationError:
                        traceback.print_exc()
                        print(
                            f"failed to parse scan at line {line}, ignoring this scan"
                        )
    return scans


def generate_report_for_user(
    ctx: ReportCtx,
    bundle: UserBundle,
) -> ScanReport:
    for i in range(0, len(ctx.revscandb)):
        scan = ctx.getscan(i, bundle.id)
        if scan is not None:
            scantime = str(ctx.revscandb[i].scantime)
            if ctx.check_prev_scans:
                # Chequear hashes pasados de los contenidos del archivo
                for item in scan.values():
                    current_hash = item.fsinfo.contents
                    if isinstance(current_hash, list):
                        continue
                    for j in range(i + 1, len(ctx.revscandb)):
                        older_hash = None
                        older_scan = ctx.getscan(j, bundle.id)
                        if older_scan and item.path in older_scan:
                            older_hash = older_scan[item.path].fsinfo.contents
                        if older_hash == current_hash:
                            # Sabemos que por lo menos desde este instante hasta el presente el archivo no ha cambiado
                            item.change = min(item.change, ctx.revscandb[j].scantime)
                        else:
                            # Sabemos que hasta este instante el archivo era distinto
                            item.change = max(item.change, ctx.revscandb[j].scantime)
                            break
            items = sorted(
                scan.values(),
                key=lambda item: (item.change, not item.is_dir, item.path),
                reverse=True,
            )
            match ctx.report_mode:
                case ReportMode.all:
                    # Nothing to do
                    pass
                case ReportMode.latest:
                    # Remove all but the last
                    items = items[:1]
                case ReportMode.daily:
                    # Remove all but the newest for each day
                    last_day = (items[0].change + timedelta(days=3)).date()

                    def include_item(item: FileItem) -> bool:
                        nonlocal last_day
                        do_include = item.change.date() < last_day
                        last_day = item.change.date()
                        return do_include

                    items = [item for item in items if include_item(item)]
            has_php = any(item.path.suffix == ".php" for item in items)
            return ScanReport(
                usuario=bundle.id,
                timestamp_escaneo=scantime,
                ultimos_cambios="\n".join(
                    f"{item.change} -> {item.path}" for item in items
                ),
                tiene_archivo_php="Si" if has_php else "No",
            )
    return ScanReport(
        usuario=bundle.id,
        timestamp_escaneo="No hay escaneos para este usuario",
        ultimos_cambios="",
        tiene_archivo_php="No",
    )


@app.command("report", help="Generar un reporte de última modificación de archivos.")
def generate_report(
    group_name: Annotated[
        str | None,
        Argument(help="Generar reporte solo para los usuarios en este grupo."),
    ],
    out: Annotated[Path, Argument(help="Dónde guardar el .csv generado como reporte.")],
    *,
    config_path: Path | None = None,
    db_path: Path | None = None,
    min_time: Annotated[
        datetime | None,
        Option(help="Considerar desde este tiempo en adelante."),
    ] = None,
    max_time: Annotated[
        datetime | None, Option(help="Considerar solo hasta este tiempo.")
    ] = None,
    subdir: Annotated[Path, Option(help="Considerar solo este subdirectorio.")] = Path(
        "."
    ),
    ignore_hidden: Annotated[
        bool,
        Option(
            help="Ignorar archivos que comienzen con '.' para el cálculo de última modificación.",
        ),
    ] = True,
    consider_metadata: Annotated[
        bool,
        Option(
            help="Considerar cambios de permisos y metadatos (ctime).",
        ),
    ] = False,
    check_prev_scans: Annotated[
        bool, Option(help="Revisar escaneos pasados para mayor robustez.")
    ] = True,
    ignore_dirs: Annotated[
        bool, Option(help="Ignorar directorios, y considerar solo archivos.")
    ] = True,
    report_mode: Annotated[
        ReportMode,
        Option(
            help="Reportar las fechas de todos los archivos, el último de cada día, o solo el último global."
        ),
    ] = ReportMode.all,
    regex: Annotated[
        str | None,
        Option(
            help="Filtrar usando esta expresión regular. (OJO: NO es un patrón normal, es un regex!)",
        ),
    ] = None,
    timezone: str = "America/Santiago",
):
    compiled_regex = None if regex is None else re.compile(regex)
    tz = ZoneInfo(timezone)
    if min_time is not None:
        min_time = min_time.astimezone(tz)
    if max_time is not None:
        max_time = max_time.astimezone(tz)

    config = sync_state(config_path=config_path)
    user_bundles = find_users_in_group(config, group_name)
    scandb = read_scandb(db_path, min_time, max_time, tz)

    if not user_bundles:
        if sum(len(group.users) for group in config.groups) == 0:
            print("No hay usuarios en el sistema. No se generó ningún reporte.")
        elif user_bundles is not None:
            print(f"No hay usuarios en el grupo {group_name}.")
        else:
            print(f'No existe el grupo "{group_name}".')
        return

    if not scandb:
        print(
            "No hay escaneos"
            + (" dentro de las fechas entregadas" if min_time or max_time else "")
            + ". No se generó ningún reporte."
        )
        return
    revscandb = sorted(scandb, key=lambda scan: scan.scantime, reverse=True)
    print(f"Usando {len(scandb)} escaneos, el último con fecha {revscandb[0].scantime}")

    ctx = ReportCtx(
        revscandb=revscandb,
        cachedscans={},
        subdir=subdir,
        ignore_hidden=ignore_hidden,
        use_ctime=consider_metadata,
        ignore_dirs=ignore_dirs,
        check_prev_scans=check_prev_scans,
        regex=compiled_regex,
        report_mode=report_mode,
        timezone=tz,
    )
    report: list[ScanReport] = []
    user_bundles.sort(key=lambda bundle: bundle.id)
    for bundle in user_bundles:
        report.append(generate_report_for_user(ctx, bundle))

    with exception_context(f"writing userscan report at {out}"):
        with out.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=list(ScanReport.model_json_schema()["properties"].keys()),
            )
            writer.writeheader()
            for user_report in report:
                writer.writerow(user_report.model_dump())
    print(
        f"se genero un reporte de {len(report)} usuarios a partir de {len(scandb)} escaneos"
    )
