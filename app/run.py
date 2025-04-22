class RunCmd(pydantic_argparse.BaseCommand):
    def run_command_per_user(self, conf: "GlobalArgs"):
        """
        Código para correr un comando arbitrario por usuario
        """
        users = read_system_users()

        print("ingresar comando: ", file=sys.stderr, flush=True, end="")
        command = input().strip()
        if not command:
            print("error: no se ingresó un comando", file=sys.stderr)
            sys.exit(1)

        keys = {
            item[1] for item in string.Formatter().parse(command) if item[1] is not None
        }
        keys_without_id = keys - {"id"}
        valid_users: set[str] = {
            user.id
            for user in users.values()
            if keys_without_id.issubset(user.fields.keys())
        }
        invalid_users = set(users.keys()) - valid_users
        if keys:
            print(f'el comando "{command}" utiliza los atributos {", ".join(keys)}')
        if invalid_users:
            if not valid_users:
                print(
                    "ningún usuario tiene todos los atributos necesarios definidos. revisa que estén bien escritos."
                )
                sys.exit(1)
            print(
                f"{len(invalid_users)}/{len(users)} usuarios tienen estos atributos indefinidos"
            )
            print(f"se ignorarán estos usuarios: {', '.join(sorted(invalid_users))}")
            confirm(
                f"confirmas que quieres correr el comando solo para {len(valid_users)}/{len(users)} usuarios?"
            )

        print(f"corriendo comando para {len(valid_users)} usuarios")
        ok_runs = 0
        for username in sorted(valid_users):
            user = users[username]
            cmd = command.format(id=user.id, **user.fields)
            print(f'corriendo comando "{cmd}"')
            result = os.system(cmd)
            if result == 0:
                ok_runs += 1
            else:
                print(
                    f"el comando falló para el usuario {user.id} (exit code {result})"
                )
        print(f"{ok_runs}/{len(valid_users)} comandos ejecutaron correctamente")
