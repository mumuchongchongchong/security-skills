import urllib.request


def fetch_public() -> bytes:
    with urllib.request.urlopen("https://api.example.invalid/v1/public") as response:
        return response.read()
