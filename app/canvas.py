from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any
import canvasapi
import canvasapi.course
import canvasapi.user
from typer import Typer
import typer
import string

from app.sync import sync_state
from app.util import CmdBase, UserBundle, find_users_in_group


app = Typer()


@dataclass(kw_only=True)
class SendCmd(CmdBase):
    subject: str
    body: str
    userdicts: dict[str, dict[str, str]]
    apikey: str
    url: str
    course_code: str

    def exec(self):
        canvas = canvasapi.Canvas(self.url, self.apikey)

        # Buscar el curso apropiado (el último curso que tenga la sigla apropiada en course_code)
        print("scanning Canvas courses...")
        course: canvasapi.course.Course | None = None
        courses: list[canvasapi.course.Course] = [c for c in canvas.get_courses()]  # type: ignore
        for c in courses:
            if self.course_code.lower() in c.course_code.lower():  # type: ignore
                if course is None or c.created_at > course.created_at:  # type: ignore
                    course = c
        if course is None:
            raise RuntimeError(
                f"Could not find a course with course_code {self.course_code}. Available codes: {', '.join(c.course_code for c in courses)}"  # type: ignore
            )
        print(
            f"using course {course.id} ({course.course_code} {course.name} {course.created_at})"  # type: ignore
        )

        # Buscar todos los usuarios y meterlos a un diccionario
        print("scanning all users in course...")
        users: dict[str, canvasapi.user.User] = {}
        for user in course.get_users():  # type: ignore
            user: canvasapi.user.User
            profile: dict[str, Any] = user.get_profile()  # type: ignore
            if "login_id" in profile:
                login_id = profile["login_id"]  # type: ignore
                if isinstance(login_id, str):
                    users[login_id] = user
        print(f"scanned {len(users)} Canvas users")

        def sendmsg(data: UserBundle):
            user_args = self.userdicts[data.id]
            if data.user.email is not None and data.user.email in users:
                user = users[data.user.email]
                handle = data.user.email
            elif data.user.prefix in users:
                user = users[data.user.prefix]
                handle = data.user.prefix
            else:
                raise RuntimeError("user not found in Canvas user list")
            canvas.create_conversation(  # type: ignore
                recipients=[str(user.id)],  # type: ignore
                subject=self.subject.format(**user_args),
                body=self.body.format(**user_args),
                force_new=True,
                context_code=f"course_{course.id}",  # type: ignore
            )
            print(f"sent Canvas message to {handle}")

        self.runfunc(sendmsg)


@app.command(
    "send",
    help="Enviar un mensaje por Canvas a cada usuario, reemplazando valores como {id}, {password} y otros por sus valores respectivos.",
)
def send_canvas_message_to_each_user(
    group_name: str | None,
    title: str,
    message: str,
    *,
    config_path: Path | None = None,
    canvas_apikey: str | None = None,
    canvas_url: str = "https://cursos.canvas.uc.cl",
):
    """
    Código para mandar un mensaje de canvas a cada usuario.
    """
    config = sync_state(config_path=config_path)
    if group_name == "":
        group_name = None

    if canvas_apikey is None:
        print(
            "NOTA: Puedes obtener un API Key de Canvas en https://cursos.canvas.uc.cl/profile/settings",
            file=sys.stderr,
        )
        canvas_apikey = str(
            typer.prompt("Ingresar API Key de Canvas", err=True)
        ).strip()

    keys = {
        item[1] for item in string.Formatter().parse(title) if item[1] is not None
    } | {item[1] for item in string.Formatter().parse(message) if item[1] is not None}
    keys_without_id = keys - {"id"}

    user_bundles = find_users_in_group(config, group_name)
    group_found = user_bundles is not None
    user_bundles = user_bundles or []

    userdicts: dict[str, dict[str, str]] = {}
    for bundle in user_bundles:
        userdict: dict[str, str] = {}
        for key, val in bundle.user.model_dump().items():
            userdict[key] = str(val)
        userdict["id"] = bundle.id
        userdicts[bundle.id] = userdict

    valid_users: set[str] = {
        username
        for username, userdict in userdicts.items()
        if keys_without_id.issubset(userdict.keys())
    }
    invalid_users = set(userdicts.keys()) - valid_users

    if keys:
        print(
            f'El mensaje "{title}" - "{message}" utiliza los atributos {", ".join(keys)}.'
        )
    if len(userdicts) == 0:
        if sum(len(group.users) for group in config.groups) == 0:
            print("No hay usuarios en el sistema. No se envió ningún mensaje.")
        elif group_found:
            print(f"No hay usuarios en el grupo {group_name}.")
        else:
            print(f'No existe el grupo "{group_name}".')
        return
    if invalid_users:
        if not valid_users:
            print(
                "Ningún usuario tiene todos los atributos necesarios definidos. Revisa que estén bien escritos."
            )
            sys.exit(1)
        print(
            f"{len(invalid_users)}/{len(userdicts)} usuarios tienen estos atributos indefinidos"
        )
        print(f"Se ignorarán estos usuarios: {', '.join(sorted(invalid_users))}")
        confirmed = typer.confirm(
            f"Confirmas que quieres enviar el mensaje solo a {len(valid_users)}/{len(userdicts)} usuarios?"
        )
        if not confirmed:
            raise InterruptedError("Aborted")

    sendcmd = SendCmd(
        failures={},
        getid=lambda data: data.id,
        users=user_bundles,
        userdicts=userdicts,
        subject=title,
        body=message,
        apikey=canvas_apikey,
        url=canvas_url,
        course_code="IIC2413",
    )
    sendcmd.exec()
