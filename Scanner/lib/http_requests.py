import requests
import random
import time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/15.15063",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko) Safari/603.2.4",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.0 Mobile/14F89 Safari/602.1"
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def fetch_url(url, method='GET'):
    headers = {
        "User-Agent": get_random_user_agent()
    }
    if not url.startswith(('http://', 'https://')):
        try:
            # Primeiro tenta com HTTPS
            test_url = 'https://' + url
            response = requests.request(method, test_url, headers=headers, timeout=5)
            if response.ok:
                return response
        except requests.exceptions.RequestException:
            # Se HTTPS falhar, tenta com HTTP
            try:
                test_url = 'http://' + url
                response = requests.request(method, test_url, headers=headers, timeout=5)
                if response.ok:
                    return response
            except requests.exceptions.RequestException as e:
                print(f"Erro ao conectar a {url} com ambos HTTP e HTTPS: {e}")
                return None
    else:
        try:
            response = requests.request(method, url, headers=headers, timeout=5)
            if response.ok:
                return response
        except requests.exceptions.RequestException as e:
            print(f"Erro ao conectar a {url}: {e}")
            return None
    return None
