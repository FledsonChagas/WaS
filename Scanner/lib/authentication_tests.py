import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
from tqdm import tqdm
import os
from threading import Thread, Lock
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
from .http_requests import fetch_url

lock = Lock()

def load_common_credentials():
    credentials_path = os.path.join(os.path.dirname(__file__), 'SecList', 'Passwords', 'xato-net-10-million-passwords-dup.txt')
    if not os.path.exists(credentials_path):
        raise FileNotFoundError(f"O arquivo 'xato-net-10-million-passwords-dup.txt' não foi encontrado em: {credentials_path}")
    with open(credentials_path, 'r', encoding='latin-1') as file:
        return [line.strip().split(':') for line in file if ':' in line.strip()]

def load_sqli_payloads():
    payloads_path = os.path.join(os.path.dirname(__file__), 'SecList', 'Fuzzing', 'SQLi', 'quick-SQLi.txt')
    if not os.path.exists(payloads_path):
        raise FileNotFoundError(f"O arquivo 'quick-SQLi.txt' não foi encontrado em: {payloads_path}")
    with open(payloads_path, 'r', encoding='latin-1') as file:
        return [line.strip() for line in file if line.strip()]

common_credentials = load_common_credentials()
sqli_payloads = load_sqli_payloads()

def identify_login_forms(html):
    soup = BeautifulSoup(html, 'html.parser')
    login_forms = []

    forms = soup.findAll('form')
    for form in forms:
        inputs = form.findAll('input')
        has_username = any(input_tag.get('type') == 'text' for input_tag in inputs)
        has_password = any(input_tag.get('type') == 'password' for input_tag in inputs)
        if has_username and has_password:
            login_forms.append(form)

    return login_forms

def test_login_form(url, form, progress_bar, results):
    action = form.get('action') or url
    action = urljoin(url, action)
    method = form.get('method', 'post').lower()

    for username, password in common_credentials:
        form_data = {input_tag.get('name'): (username if input_tag.get('type') == 'text' else password)
                     for input_tag in form.findAll('input') if input_tag.get('name')}

        try:
            response = requests.request(method, action, data=form_data)
            if "invalid" not in response.text.lower():  # Simplistic check, adjust as needed
                with lock:
                    results.append({
                        'url': url,
                        'action': action,
                        'username': username,
                        'password': password,
                        'response': response.text
                    })
        except requests.RequestException as e:
            with lock:
                results.append({'url': url, 'error': str(e)})

        with lock:
            progress_bar.update(1)

def test_sqli_form(url, form, progress_bar, results):
    action = form.get('action') or url
    action = urljoin(url, action)
    method = form.get('method', 'post').lower()

    for payload in sqli_payloads:
        form_data = {input_tag.get('name'): (payload if input_tag.get('type') == 'text' else 'password')
                     for input_tag in form.findAll('input') if input_tag.get('name')}

        try:
            response = requests.request(method, action, data=form_data)
            if "syntax error" in response.text.lower():  # Simplistic check, adjust as needed
                with lock:
                    results.append({
                        'url': url,
                        'action': action,
                        'payload': payload,
                        'response': response.text
                    })
        except requests.RequestException as e:
            with lock:
                results.append({'url': url, 'error': str(e)})

        with lock:
            progress_bar.update(1)

def test_authentication(url):
    response = fetch_url(url)
    if not response:
        print(f"Falha ao conectar a {url}")
        return

    html = response.text
    login_forms = identify_login_forms(html)

    if not login_forms:
        print("Nenhum formulário de login encontrado.")
        return

    results = []
    threads = []
    total_attempts = len(login_forms) * (len(common_credentials) + len(sqli_payloads))
    progress_bar = tqdm(total=total_attempts, desc="Testando autenticação", unit="tentativa")

    for form in login_forms:
        thread = Thread(target=test_login_form, args=(url, form, progress_bar, results))
        threads.append(thread)
        thread.start()

        thread = Thread(target=test_sqli_form, args=(url, form, progress_bar, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    progress_bar.close()

    print("\nResultados dos testes de autenticação:")
    for result in results:
        if 'error' not in result:
            print(result)
