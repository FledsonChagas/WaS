import requests

def fetch_url(url):
    try:
        response = requests.get(url, timeout=5)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Erro ao conectar a {url}: {e}")
        return None
