from bs4 import BeautifulSoup, Comment
import re
from tqdm import tqdm
import json
import os

def load_sensitive_keywords():
    directory_of_this_script = os.path.dirname(__file__)
    seclists_path = os.path.join(directory_of_this_script, 'SecList', 'Discovery', 'Web-Content', 'burp-parameter-names.txt')
    if not os.path.exists(seclists_path):
        raise FileNotFoundError(f"O arquivo '{seclists_path}' não foi encontrado.")
    with open(seclists_path, 'r', encoding='latin-1') as file:
        keywords = [line.strip() for line in file if line.strip()]
    return keywords

def analyze_content(html):
    soup = BeautifulSoup(html, 'html.parser')
    sensitive_keywords = load_sensitive_keywords()

    result = {
        "comments": [],
        "forms": [],
        "scripts": [],
        "links": [],
        "external_links": [],
        "metadata": []
    }

    tasks = [
        ("Detecção de Comentários", lambda: analyze_comments(soup, result, sensitive_keywords)),
        ("Identificação de Formulários", lambda: analyze_forms(soup, result)),
        ("Busca por Scripts", lambda: analyze_scripts(soup, result)),
        ("Busca por Links", lambda: analyze_links(soup, result)),
        ("Verificação de Links Externos", lambda: analyze_external_links(soup, result)),
        ("Detecção de Metadados", lambda: analyze_metadata(soup, result)),
    ]

    progress_bar = tqdm(total=len(tasks), desc="Analisando conteúdo", unit="task")
    for task_name, task_func in tasks:
        task_func()
        progress_bar.update(1)
    progress_bar.close()

    print(json.dumps(result, indent=4))

def analyze_comments(soup, result, sensitive_keywords):
    comments = soup.findAll(text=lambda text: isinstance(text, Comment))
    for comment in comments:
        comment_data = {
            "text": comment,
            "type": "sensitive" if any(keyword in comment.lower() for keyword in sensitive_keywords) else "normal"
        }
        result["comments"].append(comment_data)

def analyze_forms(soup, result):
    forms = soup.findAll('form')
    for form in forms:
        form_data = {
            "method": form.get('method', 'GET').upper(),
            "action": form.get('action', 'N/A'),
            "fields": [],
            "csrf_token_found": bool(form.findAll('input', {'name': re.compile('csrf', re.IGNORECASE)}))
        }
        inputs = form.findAll(['input', 'textarea', 'select'])
        for input_tag in inputs:
            field_data = {
                "type": input_tag.get('type', input_tag.name),
                "name": input_tag.get('name', 'N/A')
            }
            form_data["fields"].append(field_data)
        result["forms"].append(form_data)

def analyze_scripts(soup, result):
    scripts = soup.findAll('script')
    for script in scripts:
        script_data = {
            "type": "external" if script.get('src') else "embedded",
            "src": script.get('src'),
            "content": script.string if script.string else "N/A"
        }
        result["scripts"].append(script_data)

def analyze_links(soup, result):
    links = soup.findAll('a')
    for link in links:
        href = link.get('href', None)
        link_data = {
            "type": "suspicious" if href and any(keyword in href.lower() for keyword in ['login', 'admin', 'secure']) else "normal",
            "href": href
        }
        result["links"].append(link_data)

def analyze_external_links(soup, result):
    external_links = [link.get('href') for link in soup.findAll('a') if link.get('href', '').startswith('http')]
    result["external_links"].extend(external_links)

def analyze_metadata(soup, result):
    metas = soup.findAll('meta')
    for meta in metas:
        meta_data = {
            "name": meta.get('name', 'N/A'),
            "content": meta.get('content', 'N/A')
        }
        result["metadata"].append(meta_data)
