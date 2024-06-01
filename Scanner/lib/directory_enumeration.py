from .http_requests import fetch_url
from threading import Thread, Lock, Semaphore
import os
from tqdm import tqdm
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import random
import time

lock = Lock()
visited_urls = set()
max_threads = 60  # Número máximo de threads simultâneas
semaphore = Semaphore(max_threads)
custom_404_text = ""

http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']

def load_common_paths():
    directory_of_this_script = os.path.dirname(__file__)
    path_to_common_paths = os.path.join(directory_of_this_script, 'RedList', 'Discovery', 'Web-Content', 'common.txt')
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

def check_path(url, results, progress_bar, methods):
    for method in methods:
        response = fetch_url(url, method=method)
        if response and response.status_code == 200 and not is_custom_404(response):
            with lock:
                results.append((url, method, response.status_code))
                # Extrair subdiretórios encontrados para escaneamento adicional
                if 'text/html' in response.headers.get('Content-Type', ''):
                    subdirs = extract_subdirectories(response.text, url)
                    for subdir in subdirs:
                        full_url = urljoin(url, subdir)
                        if full_url not in visited_urls:
                            visited_urls.add(full_url)
                            time.sleep(random.uniform(0.1, 1.0))  # Atraso aleatório entre 100ms e 1s
                            thread = Thread(target=check_path, args=(full_url, results, progress_bar, methods))
                            semaphore.acquire()
                            thread.start()
                            threads.append(thread)
                break
    with lock:
        progress_bar.update(1)
    semaphore.release()

def extract_subdirectories(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    subdirs = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)
        path = parsed_url.path
        if path and not path.startswith(('/', 'http:', 'https:', '#')):
            subdirs.add(path)
    return subdirs

def directory_enumeration(url):
    detect_custom_404(url)
    common_paths = load_common_paths()
    results = []
    threads = []
    progress_bar = tqdm(total=len(common_paths), desc="Buscando diretórios expostos", unit="dir")

    # Verificar caminhos comuns
    for path in common_paths:
        full_url = f"{url}/{path}"
        if full_url not in visited_urls:
            visited_urls.add(full_url)
            time.sleep(random.uniform(0.1, 1.0))  # Atraso aleatório entre 100ms e 1s
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
                subdirs = extract_subdirectories(response.text, result[0])
                if subdirs:
                    print(f"Subdiretórios encontrados: {', '.join(subdirs)}")