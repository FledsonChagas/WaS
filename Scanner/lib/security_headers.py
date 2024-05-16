def check_security_headers(headers):
    security_headers = {
        'Strict-Transport-Security': "Protege contra ataques man-in-the-middle",
        'X-Frame-Options': "Protege contra clickjacking",
        'X-Content-Type-Options': "Previne o MIME type sniffing",
        'Content-Security-Policy': "Reduz riscos de cross-site scripting e outros ataques"
    }

    missing_headers = {h: desc for h, desc in security_headers.items() if h not in headers}
    print("Cabeçalhos de segurança presentes e suas configurações:")
    for header, desc in missing_headers.items():
        print(f"{header}: {desc}")

def analyze_cookies(headers):
    if 'Set-Cookie' in headers:
        cookies = headers.get('Set-Cookie')
        if 'HttpOnly' not in cookies or 'Secure' not in cookies:
            print("Cookies não estão configurados corretamente com HttpOnly e Secure.")
    else:
        print("Nenhum cookie configurado.")
