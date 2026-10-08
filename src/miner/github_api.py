import os
import time
import requests
from typing import List, Dict
from urllib.parse import quote, urlparse

API_HOST = "api.github.com"

# Reintentos ante límites de la API de GitHub (403/429).
_MAX_RETRIES = 5
_MAX_BACKOFF = 60  # segundos


def _retry_delay(response: "requests.Response", attempt: int) -> float:
    """Calcula la espera antes de reintentar respetando las cabeceras de GitHub."""
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF)
        except (TypeError, ValueError):
            pass
    reset = response.headers.get("X-RateLimit-Reset")
    if reset:
        try:
            delay = float(reset) - time.time()
            if delay > 0:
                return min(delay, _MAX_BACKOFF)
        except (TypeError, ValueError):
            pass
    return min(2 ** attempt, _MAX_BACKOFF)


def _get_with_backoff(url: str, headers: Dict, params) -> "requests.Response":
    """GET con backoff exponencial ante 403/429 (límite de la API de GitHub)."""
    for attempt in range(_MAX_RETRIES):
        response = requests.get(url, headers=headers, params=params, timeout=30)
        try:
            response.raise_for_status()
            return response
        except requests.HTTPError:
            status = getattr(response, "status_code", None)
            if status in (403, 429) and attempt < _MAX_RETRIES - 1:
                time.sleep(_retry_delay(response, attempt))
                continue
            raise

# Orden por defecto con el que GitHub muestra los repositorios de una
# organización (página "Repositories"): los actualizados más recientemente
# primero. La API lo expone con sort=updated y direction=desc.
DEFAULT_REPO_SORT = "updated"
DEFAULT_REPO_DIRECTION = "desc"

def get_github_token() -> str:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("La variable de entorno GITHUB_TOKEN no está configurada.")
    return token

def get_organization_repos(
    org_name: str,
    sort: str = DEFAULT_REPO_SORT,
    direction: str = DEFAULT_REPO_DIRECTION,
) -> List[Dict]:
    """Lista los repositorios de una organización en el mismo orden que GitHub.

    Por defecto usa ``sort=updated`` y ``direction=desc``, que es el orden con
    el que la página de repositorios de la organización los muestra (los
    actualizados más recientemente primero). Los repositorios se devuelven en
    ese orden, de modo que aplicar un límite a la lista equivale a quedarse con
    los primeros N tal y como los presenta GitHub.
    """
    token = get_github_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    repos = []
    seen_ids = set()
    url = f"https://api.github.com/orgs/{quote(org_name, safe='')}/repos"
    params = {"per_page": 100, "type": "all", "sort": sort, "direction": direction}
    
    while url:
        response = _get_with_backoff(url, headers, params)
        for repo in response.json():
            repo_id = repo.get("id")
            # 'updated' no es una clave única ni estable: si un repositorio se
            # actualiza durante la paginación puede repetirse entre páginas.
            # Se deduplica por 'id' conservando el orden de GitHub.
            if repo_id is not None:
                if repo_id in seen_ids:
                    continue
                seen_ids.add(repo_id)
            repos.append(repo)
        
        # Paginación mediante el header 'Link'
        url = None
        if "Link" in response.headers:
            links = response.headers["Link"].split(", ")
            for link in links:
                if 'rel="next"' in link:
                    next_url = link[link.index("<")+1 : link.index(">")]
                    # No reenviar el token a un host distinto de api.github.com
                    # ni por un esquema no seguro.
                    parsed = urlparse(next_url)
                    if parsed.scheme == "https" and parsed.hostname == API_HOST:
                        url = next_url
                        params = None # Los parámetros ya vienen en la URL del link
                    break
                    
    return repos
