import json
from datetime import datetime
import socket

def analyze_hsts(header_value):
    """Analisa o cabeçalho Strict-Transport-Security para verificar configurações recomendadas."""
    issues = []
    directives = header_value.split(';')
    max_age_found = False
    for directive in directives:
        if directive.strip().startswith('max-age'):
            max_age_found = True
            age = int(directive.split('=')[1])
            if age < 31536000:  # Recomenda-se um ano (31536000 segundos)
                issues.append(f"max-age muito baixo ({age} segundos). Recomenda-se um mínimo de 31536000 segundos.")
    if not max_age_found:
        issues.append("max-age não especificado.")
    if 'includeSubDomains' not in header_value:
        issues.append("Aviso: 'includeSubDomains' não encontrado.")
    return issues

def analyze_csp(csp_value):
    """Analisa detalhadamente a política de segurança de conteúdo."""
    issues = []
    if "'unsafe-inline'" in csp_value:
        issues.append("CSP contém 'unsafe-inline' que é inseguro para scripts.")
    if "'unsafe-eval'" in csp_value:
        issues.append("CSP contém 'unsafe-eval' que é inseguro para scripts.")

    # Verificar se o CSP é restritivo o suficiente
    if 'default-src' in csp_value:
        if "'self'" not in csp_value:
            issues.append("CSP default-src não é restrito a 'self'.")
    else:
        issues.append("CSP não define 'default-src'.")

    return issues

def analyze_x_frame_options(header_value):
    """Analisa o cabeçalho X-Frame-Options."""
    if header_value not in ["DENY", "SAMEORIGIN"]:
        return [f"Valor não recomendado ({header_value}). Deve ser 'DENY' ou 'SAMEORIGIN'."]
    return []

def analyze_x_content_type_options(header_value):
    """Analisa o cabeçalho X-Content-Type-Options."""
    if header_value != "nosniff":
        return [f"Valor não recomendado ({header_value}). Deve ser 'nosniff'."]
    return []

def analyze_x_xss_protection(header_value):
    """Analisa o cabeçalho X-XSS-Protection."""
    if header_value != "1; mode=block":
        return [f"Valor não recomendado ({header_value}). Deve ser '1; mode=block'."]
    return []

def industry_benchmark(headers):
    """Compara os cabeçalhos de segurança encontrados com as práticas recomendadas da indústria."""
    recommended_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    missing = [h for h in recommended_headers if h.lower() not in headers]
    return missing

def get_ip_address(url):
    """Obtém o endereço IP a partir da URL."""
    try:
        return socket.gethostbyname(url.split('//')[-1].split('/')[0])
    except socket.error:
        return "IP não encontrado"

def calculate_security_grade(missing_count):
    """Calcula a nota de segurança com base no número de cabeçalhos ausentes."""
    if missing_count == 0:
        return "A+"
    elif missing_count == 1:
        return "A"
    elif missing_count == 2:
        return "B"
    elif missing_count == 3:
        return "C"
    elif missing_count == 4:
        return "D"
    elif missing_count == 5:
        return "E"
    else:
        return "F"

def get_security_message(grade):
    """Retorna uma mensagem apropriada com base na nota de segurança."""
    if grade == "A":
        return "Great grade! Your security posture is excellent."
    elif grade == "B":
        return "Good job! Your security posture is good, but there's room for improvement."
    elif grade == "C":
        return "Fair grade. Your security posture is okay, but there are some issues to address."
    elif grade == "D":
        return "Poor grade. You should improve your security posture."
    elif grade == "E":
        return "Very poor grade. Immediate improvements are needed for your security posture."
    else:
        return "Ouch, you should work on your security posture immediately."

def check_security_headers(headers, url):
    headers = {k.lower(): v for k, v in headers.items()}  # Converte as chaves dos cabeçalhos para minúsculas
    results = {}
    security_headers = {
        'strict-transport-security': ("Protege contra ataques man-in-the-middle, deve incluir 'max-age' e 'includeSubDomains'", analyze_hsts),
        'x-frame-options': ("Protege contra clickjacking, deve ser 'DENY' ou 'SAMEORIGIN'", analyze_x_frame_options),
        'x-content-type-options': ("Previne o MIME type sniffing, deve ser 'nosniff'", analyze_x_content_type_options),
        'content-security-policy': ("Reduz riscos de cross-site scripting e outros ataques, deve ser configurado de forma estrita", analyze_csp),
        'x-xss-protection': ("Protege contra ataques XSS, deve ser '1; mode=block'", analyze_x_xss_protection),
        'referrer-policy': ("Controla informações de referência enviadas junto com as requisições, deve ser 'no-referrer' ou 'strict-origin-when-cross-origin'", None),
        'permissions-policy': ("Controla quais funcionalidades e APIs podem ser usadas no navegador", None)
    }

    for header, (description, func) in security_headers.items():
        if header in headers:
            results[header] = {
                "status": "presente",
                "value": headers[header],
                "description": description
            }
            if func:
                issues = func(headers[header])
                results[header]["issues"] = issues
        else:
            results[header] = {
                "status": "faltando",
                "description": description
            }

    cookie_analysis = analyze_cookies(headers)
    results["cookies"] = cookie_analysis

    missing_headers = industry_benchmark(headers)
    results["missing_recommended_headers"] = missing_headers
    missing_count = len(missing_headers)
    security_grade = calculate_security_grade(missing_count)
    security_message = get_security_message(security_grade)

    ip_address = get_ip_address(url)
    report_time = datetime.utcnow().strftime('%d %b %Y %H:%M:%S UTC')

    report = {
        "Security Report Summary": security_grade,
        "Site": url,
        "IP Address": ip_address,
        "Report Time": report_time,
        "Headers": list(headers.keys()),
        "Advanced": {
            security_message: {
                "Missing Headers": results["missing_recommended_headers"],
                "Cookie Analysis": cookie_analysis
            }
        },
        "Raw Headers": headers
    }

    return report

def analyze_cookies(headers):
    headers = {k.lower(): v for k, v in headers.items()}  # Converte as chaves dos cabeçalhos para minúsculas
    results = {
        'cookies': [],
        'issues': []
    }

    if 'set-cookie' in headers:
        cookies = headers['set-cookie'].split(',')
        for cookie in cookies:
            cookie_data = {}
            parts = cookie.split(';')
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    cookie_data[key.strip().lower()] = value.strip()
                else:
                    cookie_data[part.strip().lower()] = True

            results['cookies'].append(cookie_data)

            if 'httponly' not in cookie_data:
                results['issues'].append("Aviso: Cookie sem flag HttpOnly.")
            if 'secure' not in cookie_data:
                results['issues'].append("Aviso: Cookie sem flag Secure.")
            if 'samesite' not in cookie_data:
                results['issues'].append("Aviso: Cookie sem flag SameSite.")
            else:
                samesite_value = cookie_data['samesite'].lower()
                if samesite_value not in ['lax', 'strict', 'none']:
                    results['issues'].append(f"Aviso: Cookie com flag SameSite inválida ({samesite_value}). Deve ser 'Lax', 'Strict' ou 'None'.")

    else:
        results['issues'].append("Nenhum cookie configurado.")

    return results
