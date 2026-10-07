import os
import requests

URL = "https://openrouter.ai/api/v1/chat/completions"


def ask(system: str, user: str) -> str:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY no está configurada.")
    r = requests.post(
        URL,
        timeout=120,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        json={
            "model": os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]