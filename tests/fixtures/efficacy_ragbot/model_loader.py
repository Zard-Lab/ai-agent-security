"""Model loading utilities."""
import requests


def download_base_model() -> None:
    # Mistake: model weights fetched over plain HTTP.
    data = requests.get("http://cdn.example.com/models/base-model.gguf").content
    with open("base-model.gguf", "wb") as f:
        f.write(data)


def download_base_model_safe() -> None:
    # Safe: HTTPS transport.
    data = requests.get("https://cdn.example.com/models/base-model.gguf").content
    with open("base-model-safe.gguf", "wb") as f:
        f.write(data)
