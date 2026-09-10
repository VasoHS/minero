import os
import requests
from typing import List, Dict

def get_github_token() -> str:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("La variable de entorno GITHUB_TOKEN no está configurada.")
    return token

def get_organization_repos(org_name: str) -> List[Dict]:
    token = get_github_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    repos = []
    url = f"https://api.github.com/orgs/{org_name}/repos"
    params = {"per_page": 100, "type": "all"}
    
    while url:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        repos.extend(response.json())
        
        # Paginación mediante el header 'Link'
        url = None
        if "Link" in response.headers:
            links = response.headers["Link"].split(", ")
            for link in links:
                if 'rel="next"' in link:
                    url = link[link.index("<")+1 : link.index(">")]
                    params = None # Los parámetros ya vienen en la URL del link
                    break
                    
    return repos
