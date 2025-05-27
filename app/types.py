from datetime import datetime
from pathlib import Path
import re
from typing import Annotated, Any
from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    model_validator,
)

Percentage = Annotated[str, StringConstraints(pattern=r"^\d+%$")]

EMAIL_PATTERN = re.compile(r"^([^@]+)@([^.]+(?:\.[^.]+)+)$")
USERSTR_SIGNATURE_PATTERN = re.compile(r"bdd-manage-user-([0-9a-f])")
USERNAME_PATTERN = re.compile(r"(.+)\.([^.]*)")

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / ".users.json"
DEFAULT_SCANS_PATH = Path(__file__).parent.parent / ".scandb.jsonl.gz"


class UserConfigBase(BaseModel):
    memory_high: Percentage = "3%"
    memory_max: Percentage = "4%"
    cpu_quota: Percentage = "50%"
    template: Path = Path("")
    force_password: bool = False
    connection_limit: Annotated[int, Field(ge=0)] = 6

    def get_systemd_slice(self) -> str:
        raw = f"""
        # Limitar uso de memoria y CPU de los usuarios
        [Slice]
        MemoryHigh={self.memory_high}
        MemoryMax={self.memory_max}
        CPUQuota={self.cpu_quota}
        """
        return "\n".join(map(str.strip, raw.splitlines())) + "\n"


class UserConfig(UserConfigBase):
    prefix: Annotated[
        str, StringConstraints(pattern=r"[a-zA-Z][a-zA-Z0-9.\-_]{0,22}[a-zA-Z0-9]?")
    ]
    email: Annotated[str, StringConstraints(pattern=EMAIL_PATTERN)] | None = None
    password: Annotated[
        str, StringConstraints(pattern=r"[ !#$%&()*+,\-./0-9:;<=>?@A-Z\[\]^_a-z{|}~]+")
    ]

    @model_validator(mode="before")
    @classmethod
    def infer_id(cls, data: Any) -> Any:
        if (
            isinstance(data, dict)
            and "email" in data
            and isinstance(data["email"], str)
        ):
            email = data["email"]
            mat = EMAIL_PATTERN.fullmatch(email)
            if mat:
                data["prefix"] = mat[1]
        return data


class UserGroup(BaseModel):
    suffix: str
    users: list[UserConfig]


class Config(BaseModel):
    groups: list[UserGroup]


class SystemUser(BaseModel):
    """
    Datos sobre un usuario.
    """

    id: str
    prefix: str
    suffix: str
    fields: dict[str, str]


class SystemUsers(BaseModel):
    as_list: list[SystemUser]
    by_id: dict[str, SystemUser]
    by_group: dict[str, dict[str, SystemUser]]


class FsInfo(BaseModel):
    """
    Información compacta sobre un archivo/directorio.
    Almacena la estructura de los archivos y un hash de cada archivo, pero no los contenidos enteros.
    """

    name: str
    mtime: int
    ctime: int
    mode: int
    contents: list["FsInfo"] | str


class UserScan(BaseModel):
    """
    Datos de entrega de un usuario.
    Un snapshot de la carpeta `home` del usuario.
    """

    home: FsInfo


class Scan(BaseModel):
    """
    Un escaneo hecho en una fecha/hora particular.
    """

    scantime: datetime
    users: dict[str, UserScan]
