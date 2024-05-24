from .http_requests import fetch_url
from threading import Thread, Lock, Semaphore
import requests
from requests.exceptions import RequestException
import os
from tqdm import tqdm

lock = Lock()
semaphore = Semaphore(100)  # Número máximo de threads simultâneas
http_methods = ['GET', 'POST']
custom_404_text = ""

error_indicators = [
    'you have an error in your sql syntax;',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
    'sql error',
    'syntax error'
]


def load_sqli_payloads():
    directory_of_this_script = os.path.dirname(__file__)
    path_to_sqli_payloads = os.path.join(directory_of_this_script, 'RedList', 'Fuzzing', 'SQLi', 'quick-SQLi.txt')
    if not os.path.exists(path_to_sqli_payloads):
        raise FileNotFoundError(f"O arquivo 'sql_injection.txt' não foi encontrado em: {path_to_sqli_payloads}")
    with open(path_to_sqli_payloads, 'r', encoding='latin-1') as file:
        return [line.strip() for line in file if line.strip()]


def detect_custom_404(url):
    response = fetch_url(url + "/nonexistentpath", method='GET')
    global custom_404_text
    if response and response.status_code == 404:
        custom_404_text = response.text


def is_custom_404(response):
    return custom_404_text and custom_404_text in response.text


def fetch_url(url, method='GET', data=None):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Assume http como padrão se nenhum esquema for fornecido
    try:
        if method == 'GET':
            response = requests.get(url, timeout=5)
        elif method == 'POST':
            response = requests.post(url, data=data, timeout=5)
        return response if response.status_code not in [404] else None
    except RequestException as e:

        return None


def check_sqli(url, payload, method, results, progress_bar):
    if method == 'GET':
        full_url = f"{url}?id={payload}"
        response = fetch_url(full_url, method=method)
    elif method == 'POST':
        full_url = url
        data = {'id': payload}
        response = fetch_url(full_url, method=method, data=data)

    if response and any(error in response.text.lower() for error in error_indicators) and not is_custom_404(response):
        with lock:
            results.append((full_url, method, payload))

    with lock:
        progress_bar.update(1)
    semaphore.release()


def test_sqli(url):
    sqli_payloads = load_sqli_payloads()
    results = []
    threads = []
    total_tests = len(sqli_payloads) * len(http_methods)
    progress_bar = tqdm(total=total_tests, desc="Testando SQL Injection", unit="test")

    for payload in sqli_payloads:
        for method in http_methods:
            semaphore.acquire()
            thread = Thread(target=check_sqli, args=(url, payload, method, results, progress_bar))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    progress_bar.close()
    if results:
        print("\nPossíveis vulnerabilidades de SQLi encontradas:")
        for result in results:
            print(f"URL: {result[0]} - Método: {result[1]} - Payload: {result[2]}")
    else:
        print("\nNenhuma vulnerabilidade de SQLi encontrada.")
