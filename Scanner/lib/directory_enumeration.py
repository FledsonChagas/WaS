from .http_requests import fetch_url
from threading import Thread, Lock, Semaphore
import requests
from requests.exceptions import RequestException
import os
from tqdm import tqdm

lock = Lock()
visited_urls = set()
max_threads = 100  # Número máximo de threads simultâneas
semaphore = Semaphore(max_threads)
custom_404_text = ""

http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']

def load_common_paths():
    directory_of_this_script = os.path.dirname(__file__)
    path_to_common_paths = os.path.join(directory_of_this_script, 'seclists', 'Discovery', 'Web-Content', 'common.txt')
    if not os.path.exists(path_to_common_paths):
        raise FileNotFoundError(f"O arquivo 'common.txt' não foi encontrado em: {path_to_common_paths}")
    with open(path_to_common_paths, 'r', encoding='latin-1') as file:  # Usando encoding para suportar caracteres especiais
        return [line.strip() for line in file if line.strip()]

def detect_custom_404(url):
    response = fetch_url(url + "/nonexistentpath", method='GET')
    global custom_404_text
    if response and response.status_code == 404:
        custom_404_text = response.text

def is_custom_404(response):
    return custom_404_text and custom_404_text in response.text

def fetch_url(url, method='GET'):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Assume http como padrão se nenhum esquema for fornecido
    try:
        response = requests.request(method, url, timeout=5)
        return response if response.status_code not in [404] else None
    except RequestException as e:
        return None

def check_path(url, results, progress_bar, methods):
    for method in methods:
        response = fetch_url(url, method=method)
        if response and response.status_code == 200 and not is_custom_404(response):
            with lock:
                results.append((url, method, response.status_code))
                break
    with lock:
        progress_bar.update(1)
    semaphore.release()

def extract_subdirectories(html):
    subdirs = set()
    for line in html.splitlines():
        if 'href=' in line:
            parts = line.split('href=')
            for part in parts[1:]:
                if part.startswith('"') or part.startswith("'"):
                    part = part[1:]
                subdir = part.split('/')[0].split('?')[0].split('#')[0]
                if subdir and not subdir.startswith(('http:', 'https:', '/', '.', '#')):
                    subdirs.add(subdir)
    return subdirs

def directory_enumeration(url):
    detect_custom_404(url)
    common_paths = load_common_paths()
    results = []
    threads = []
    progress_bar = tqdm(total=len(common_paths), desc="Buscando diretórios expostos", unit="dir")

    for path in common_paths:
        full_url = f"{url}/{path}"
        if full_url not in visited_urls:
            visited_urls.add(full_url)
            semaphore.acquire()
            thread = Thread(target=check_path, args=(full_url, results, progress_bar, http_methods))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    progress_bar.close()
    if results:
        print("\nDiretórios expostos encontrados:")
        for result in results:
            print(f"URL: {result[0]} - Método: {result[1]} - Status: {result[2]}")
    else:
        print("\nNão há diretórios expostos.")

    # Relatório detalhado
    print("\nRelatório Detalhado:")
    for result in results:
        print(f"URL: {result[0]}, Método: {result[1]}, Status: {result[2]}")
        response = fetch_url(result[0], method=result[1])
        if response:
            print(f"Headers: {response.headers}")
            if 'text/html' in response.headers.get('Content-Type', ''):
                subdirs = extract_subdirectories(response.text)
                if subdirs:
                    print(f"Subdiretórios encontrados: {', '.join(subdirs)}")

