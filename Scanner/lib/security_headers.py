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


def industry_benchmark(headers):
    """Compara os cabeçalhos de segurança encontrados com as práticas recomendadas da indústria."""
    recommended_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
                           'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
    missing = [h for h in recommended_headers if h not in headers]
    if missing:
        print("Cabeçalhos de segurança recomendados faltando:", missing)
    else:
        print("Todos os cabeçalhos de segurança recomendados estão presentes.")


def check_security_headers(headers):
    security_headers = {
        'Strict-Transport-Security': (
        "Protege contra ataques man-in-the-middle, deve incluir 'max-age' e 'includeSubDomains'", analyze_hsts),
        'X-Frame-Options': ("Protege contra clickjacking, deve ser 'DENY' ou 'SAMEORIGIN'", None),
        'X-Content-Type-Options': ("Previne o MIME type sniffing, deve ser 'nosniff'", None),
        'Content-Security-Policy': (
        "Reduz riscos de cross-site scripting e outros ataques, deve ser configurado de forma estrita", analyze_csp),
        'X-XSS-Protection': ("Protege contra ataques XSS, deve ser '1; mode=block'", None),
        'Referrer-Policy': (
        "Controla informações de referência enviadas junto com as requisições, deve ser 'no-referrer' ou 'strict-origin-when-cross-origin'",
        None)
    }

    for header, (description, func) in security_headers.items():
        if header in headers:
            print(f"{header} presente, valor: {headers[header]}")
            if func:
                issues = func(headers[header])
                for issue in issues:
                    print(issue)
        else:
            print(f"{header} faltando: {description}")
    # Após verificar todos os cabeçalhos, executar o benchmarking
    industry_benchmark(headers)


def analyze_cookies(headers):
    if 'Set-Cookie' in headers:
        cookies = headers['Set-Cookie'].split(';')
        flags = {'HttpOnly': False, 'Secure': False}
        for cookie in cookies:
            if 'httponly' in cookie.lower():
                flags['HttpOnly'] = True
            if 'secure' in cookie.lower():
                flags['Secure'] = True

        if not flags['HttpOnly']:
            print("Aviso: Cookie sem flag HttpOnly.")
        if not flags['Secure']:
            print("Aviso: Cookie sem flag Secure.")
    else:
        print("Nenhum cookie configurado.")
