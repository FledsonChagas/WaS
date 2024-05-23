from .http_requests import fetch_url
from threading import Thread, Lock
import requests
from requests.exceptions import RequestException
import os
from tqdm import tqdm

lock = Lock()

def load_common_paths():
    directory_of_this_script = os.path.dirname(__file__)
    path_to_common_paths = os.path.join(directory_of_this_script, 'seclists', 'Discovery', 'Web-Content', 'common.txt')
    if not os.path.exists(path_to_common_paths):
        raise FileNotFoundError(f"O arquivo 'common.txt' não foi encontrado em: {path_to_common_paths}")
    with open(path_to_common_paths, 'r', encoding='latin-1') as file:  # Usando encoding para suportar caracteres especiais
        return [line.strip() for line in file if line.strip()]

def check_path(url, results, progress_bar):
    response = fetch_url(url)
    if response and response.status_code == 200:
        with lock:
            results.append(url)
    with lock:
        progress_bar.update(1)

def directory_enumeration(url):
    common_paths = load_common_paths()
    results = []
    threads = []
    progress_bar = tqdm(total=len(common_paths), desc="Buscando diretórios expostos", unit="dir")

    for path in common_paths:
        full_url = f"{url}/{path}"
        thread = Thread(target=check_path, args=(full_url, results, progress_bar))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    progress_bar.close()
    if results:
        print("\nDiretórios expostos encontrados:")
        for result in results:
            print(result)
    else:
        print("\nNão há diretórios expostos.")

def fetch_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Assume http como padrão se nenhum esquema for fornecido
    try:
        response = requests.get(url, timeout=5)
        return response if response.ok else None
    except RequestException as e:

        return None
