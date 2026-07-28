import subprocess
import urllib.request


def bootstrap() -> None:
    destination = "synthetic-helper.py"
    urllib.request.urlretrieve(
        "https://download.example.invalid/helper.py",
        destination,
    )
    subprocess.run(["python", destination], check=True)
