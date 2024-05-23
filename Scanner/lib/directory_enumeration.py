from .http_requests import fetch_url
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.exceptions import RequestException
import os
from tqdm import tqdm
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_seclists_paths():
    seclists_path = '../SecLists/Discovery/Web-Content/common.txt'
    if not os.path.exists(seclists_path):
        raise FileNotFoundError(f"O arquivo 'common.txt' não foi encontrado em: {seclists_path}")
    with open(seclists_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]


def check_path(url, results):
    response = fetch_url(url)
    if response and response.status_code == 200:
        results.append(url)


def directory_enumeration(url):
    common_paths = load_seclists_paths()
    results = []
    progress_bar = tqdm(total=len(common_paths), desc="Buscando diretórios expostos", unit="dir")

    with ThreadPoolExecutor(max_workers=30) as executor:  # Limita a 10 threads simultâneas
        futures = [executor.submit(check_path, f"{url}/{path}", results) for path in common_paths]
        for future in futures:
            future.result()
            progress_bar.update(1)

    progress_bar.close()
    if results:
        print("\nDiretórios expostos encontrados:")
        for result in results:
            print(result)
    else:
        print("\nNão há diretórios expostos.")


def fetch_url(url):
    session = requests.Session()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Assume http como padrão se nenhum esquema for fornecido
    try:
        response = session.get(url, timeout=5)
        return response if response.ok else None
    except RequestException as e:
        logger.error(f"Erro ao conectar a {url}: {e}")
        return None
