import requests

def fetch_url(url):
    if not url.startswith(('http://', 'https://')):
        try:
            # Primeiro tenta com HTTPS
            test_url = 'https://' + url
            response = requests.get(test_url, timeout=5)
            if response.ok:
                return response
        except requests.exceptions.RequestException:
            # Se HTTPS falhar, tenta com HTTP
            try:
                test_url = 'http://' + url
                response = requests.get(test_url, timeout=5)
                if response.ok:
                    return response
            except requests.exceptions.RequestException as e:
                print(f"Erro ao conectar a {url} com ambos HTTP e HTTPS: {e}")
                return None
    else:
        try:
            response = requests.get(url, timeout=5)
            if response.ok:
                return response
        except requests.exceptions.RequestException as e:
            print(f"Erro ao conectar a {url}: {e}")
            return None
