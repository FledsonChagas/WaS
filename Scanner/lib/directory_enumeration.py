from .http_requests import fetch_url

common_paths = ['admin', 'backup', 'config', 'login']

def directory_enumeration(url):
    for path in common_paths:
        full_url = f"{url}/{path}"
        resp = fetch_url(full_url)
        if resp and resp.status_code == 200:
            print(f"Conteúdo encontrado em: {full_url}")
        elif resp and resp.status_code == 403:
            print(f"Acesso proibido a: {full_url} (possível diretório sensível)")
