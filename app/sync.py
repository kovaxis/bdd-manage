from dataclasses import dataclass
from typer import Typer
from pathlib import Path
import subprocess
import traceback
import typer

from app.io import read_config, read_system_users
from app.types import Config
from app.util import CmdBase, UserBundle, build_userid, build_userstr_signature, ensure

app = Typer()


def reload_systemd():
    try:
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
    except subprocess.CalledProcessError:
        traceback.print_exc()
        print("failed to reload systemd daemon to update resource usage limits")


@dataclass
class CreateCmd(CmdBase):
    def exec(self):
        # Create Linux users
        self.runcmd(
            [
                "sudo",
                "useradd",
                "{username}",
                "-s",
                "/bin/bash",
                "-m",
                "-c",
                "{signature}",
            ],
            lambda data: {
                "username": data.id,
                "signature": build_userstr_signature({}),
            },
        )

        # Set initial password
        self.runcmd(
            ["sudo", "passwd", "{username}"],
            lambda data: {"username": data.id, "password": data.user.password},
            input="{password}\n{password}\n",
        )

        # Initialize home with template
        def getargs(data: UserBundle) -> dict[str, str] | None:
            if data.user.template == Path(""):
                return None
            ensure(
                data.user.template.is_dir(),
                f"template path '{data.user.template}' is not a directory",
            )
            return {
                "username": data.id,
                "templatedir": str(data.user.template),
            }

        self.runcmd("sudo cp -r {templatedir}/* /home/{username}/", getargs)

        # Configure permissions on home directory
        # (all permissions to self, read-only to the group, none to others)
        self.runcmd(
            ["sudo", "chmod", "-R", "2750", "/home/{username}"],
            lambda data: {"username": data.id},
        )
        # (setup the user's group to www-data so that apache can read from this users' home directory)
        self.runcmd(
            ["sudo", "chown", "-R", "{username}:www-data", "/home/{username}"],
            lambda data: {"username": data.id},
        )

        # Create the Postgres users
        self.runsql(
            """
            CREATE ROLE "{username}"
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                LOGIN
                NOREPLICATION
                NOBYPASSRLS
                CONNECTION LIMIT {connection_limit}
                PASSWORD '{password}';
        """,
            lambda data: {
                "username": data.id,
                "connection_limit": str(data.user.connection_limit),
                "password": data.user.password,
            },
        )

        # Create the Postgres databases
        self.runsql(
            """
            CREATE DATABASE "{username}" OWNER "{username}";
        """,
            lambda data: {
                "username": data.id,
            },
        )


@dataclass
class ConfigureCmd(CmdBase):
    def exec(self):
        # Set Linux usercomment
        self.runcmd(
            [
                "sudo",
                "usermod",
                "{username}",
                "-c",
                "{signature}",
            ],
            lambda data: {
                "username": data.id,
                "signature": build_userstr_signature({}),
            },
        )

        # Set password if forcing passwords
        self.runcmd(
            ["sudo", "passwd", "-n", "9999", "{username}"],
            lambda data: {"username": data.id, "password": data.user.password}
            if data.user.force_password
            else None,
            input="{password}\n{password}\n",
        )

        # Configure permissions on home directory
        # (all permissions to self, read-only to the group, none to others)
        # NOTE: When reconfiguring, change just the home directory, NOT RECURSIVELY
        self.runcmd(
            ["sudo", "chmod", "2750", "/home/{username}"],
            lambda data: {"username": data.id},
        )
        # (setup the user's group to www-data so that apache can read from this users' home directory)
        self.runcmd(
            ["sudo", "chown", "{username}:www-data", "/home/{username}"],
            lambda data: {"username": data.id},
        )

        # Limit memory usage
        user_uids: dict[str, str] = {
            data.id: subprocess.check_output(["id", "-u", data.id]).decode().strip()
            for data in self.users
        }
        self.runcmd(
            [
                "sudo",
                "mkdir",
                "-p",
                "/etc/systemd/system/user-{uid_numeric}.slice.d",
            ],
            lambda data: {"uid_numeric": user_uids[data.id]},
        )
        self.runcmd(
            [
                "sudo",
                "tee",
                "/etc/systemd/system/user-{uid_numeric}.slice.d/50-limit-memory.conf",
            ],
            lambda data: {
                "uid_numeric": user_uids[data.id],
                "systemd_slice": data.user.get_systemd_slice(),
            },
            input="{systemd_slice}",
        )

        # (Re)-configure the Postgres users
        self.runsql(
            """
            ALTER ROLE "{username}"
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                LOGIN
                NOREPLICATION
                NOBYPASSRLS
                CONNECTION LIMIT {connection_limit}
                {maybe_set_password};
        """,
            lambda data: {
                "username": data.id,
                "connection_limit": str(data.user.connection_limit),
                "maybe_set_password": f"PASSWORD '{data.user.password}'"
                if data.user.force_password
                else "",
            },
        )

        # Set the Postgres database owner
        self.runsql(
            """
            ALTER DATABASE "{username}" OWNER TO "{username}";
        """,
            lambda data: {
                "username": data.id,
            },
        )

        # Allow connections to the database only from its owner
        self.runsql(
            """
            REVOKE ALL PRIVILEGES ON DATABASE "{username}" FROM PUBLIC;
        """,
            lambda data: {
                "username": data.id,
            },
        )


@dataclass
class DeleteCmd(CmdBase[str]):
    sequential: bool = False

    def exec(self):
        # Get numeric UIDs for all users to destroy
        user_uids: dict[str, str] = {
            username: subprocess.check_output(["id", "-u", username]).decode().strip()
            for username in self.users
        }

        # Delete the systemd cgroup slice that limits memory usage
        self.runcmd(
            [
                "sudo",
                "rm",
                "/etc/systemd/system/user-{uid_numeric}.slice.d/50-limit-memory.conf",
            ],
            lambda username: {"uid_numeric": user_uids[username]},
        )
        self.runcmd(
            ["sudo", "rmdir", "/etc/systemd/system/user-{uid_numeric}.slice.d"],
            lambda username: {"uid_numeric": user_uids[username]},
        )

        # Delete the linux user
        self.runcmd(
            ["sudo", "deluser", "{username}", "--remove-home"],
            lambda username: {"username": username},
        )

        # Delete the user's database
        self.runsql(
            """
            DROP DATABASE "{username}";
        """,
            lambda username: {"username": username},
        )

        # Delete the user's postgres user
        self.runsql(
            """
            DROP ROLE "{username}";
        """,
            lambda username: {"username": username},
        )


def sync_state(config_path: Path | None, explicit: bool = False) -> Config:
    old_users = read_system_users()
    config = read_config(config_path)

    # Determine which actions to take
    failures: dict[str, Exception] = {}
    create = CreateCmd(failures=failures, getid=lambda data: data.id)
    configure = ConfigureCmd(failures=failures, getid=lambda data: data.id)
    new_user_ids_set: set[str] = set()
    for group in config.groups:
        for user in group.users:
            userid = build_userid(user.prefix, group.suffix)
            if userid not in old_users.by_id:
                create.users.append(CmdBase.newbundle(user, group))
            if explicit or userid not in old_users.by_id:
                configure.users.append(CmdBase.newbundle(user, group))
            new_user_ids_set.add(userid)
    destroy = DeleteCmd(failures=failures, getid=lambda username: username)
    for userid in sorted(set(user.id for user in old_users.as_list) - new_user_ids_set):
        destroy.users.append(userid)

    create_set = sorted(data.id for data in create.users)
    if create_set:
        print(f"Se crearán {len(create_set)} usuarios: {' '.join(create_set)}")
    reconf_set = sorted(
        set(data.id for data in configure.users) - set(data.id for data in create.users)
    )
    if reconf_set:
        print(f"Se reconfigurarán {len(reconf_set)} usuarios: {' '.join(reconf_set)}")
    destroy_set = sorted(destroy.users)
    if destroy_set:
        print(f"Se destruirán {len(destroy_set)} usuarios: {' '.join(destroy_set)}")
        confirmed = typer.confirm(
            f"Seguro que deseas destruir estos {len(destroy.users)} usuarios, junto con sus carpetas home?",
            False,
        )
        if not confirmed:
            raise InterruptedError("Aborted")

    if not create_set and not reconf_set and not destroy_set:
        print(f"{len(new_user_ids_set)} usuarios, nada que hacer")
        return config

    create.exec()
    configure.exec()
    destroy.exec()

    reload_systemd()
    new_users = read_system_users()

    if failures:
        print(
            f"Fallo la actualización de {len(failures)} usuarios: {' '.join(sorted(failures))}"
        )
    print(
        f"Existían {len(old_users.as_list)} usuarios de alumno, ahora existen {len(new_users.as_list)} usuarios de alumno"
    )

    return config


@app.command(
    "sync",
    help="Aplicar la configuración en el estado del servidor, creando o destruyendo cosas para calzar.",
)
def sync_state_cmd(*, config_path: Path | None = None, explicit: bool = True):
    sync_state(config_path, explicit=explicit)
