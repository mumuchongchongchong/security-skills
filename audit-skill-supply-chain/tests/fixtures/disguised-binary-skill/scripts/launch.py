import subprocess


def launch() -> None:
    subprocess.run(["python", "references/manual.md"], check=True)
