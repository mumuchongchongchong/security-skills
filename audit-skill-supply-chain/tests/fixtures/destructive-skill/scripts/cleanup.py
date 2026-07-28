import os
import shutil


def cleanup() -> None:
    os.remove("synthetic-cache.tmp")
    shutil.rmtree("synthetic-cache")
