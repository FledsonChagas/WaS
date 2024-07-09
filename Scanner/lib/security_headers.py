import json
from datetime import datetime
import socket

def analyze_hsts(header_value):
    """

    Analyze HSTS

    This method analyzes the value of the HSTS (HTTP Strict Transport Security) header and checks for any issues that might exist.

    Parameters:
    - header_value (str): The value of the HSTS header to be analyzed.

    Returns:
    - issues (list): A list of issues found in the HSTS header value.

    Note:
    - The method assumes that the header value provided is a valid HSTS header value.

    Example:
    header_value = "max-age=3600; includeSubDomains"
    issues = analyze_hsts(header_value)
    print(issues)

    Output:
    ['max-age muito baixo (3600 segundos). Recomenda-se um mínimo de 31536000 segundos.', 'Aviso: 'includeSubDomains' não encontrado.']

    """
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
    """

    Analyze the given Content Security Policy (CSP) value to identify any potential issues.

    Parameters:
    - csp_value (str): The value of the Content Security Policy (CSP) to be analyzed.

    Returns:
    - issues (list): A list of issues found in the CSP value. Each issue is represented as a string.

    Examples:
        >>> csp_value = "default-src 'self'; script-src 'unsafe-inline'"
        >>> analyze_csp(csp_value)
        ["CSP contém 'unsafe-inline' que é inseguro para scripts."]

        >>> csp_value = "default-src 'self'; script-src 'unsafe-eval'"
        >>> analyze_csp(csp_value)
        ["CSP contém 'unsafe-eval' que é inseguro para scripts."]

        >>> csp_value = "script-src 'self'; font-src 'self'"
        >>> analyze_csp(csp_value)
        ["CSP default-src não é restrito a 'self'."]

        >>> csp_value = "script-src 'self'; img-src 'self'"
        >>> analyze_csp(csp_value)
        ["CSP não define 'default-src'."]


    """
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
    """
    Analyzes the value of the X-Frame-Options header.

    This function checks if the provided header value is valid according to the X-Frame-Options specification.
    It returns a list of warning messages if the value is not 'DENY' or 'SAMEORIGIN'.

    :param header_value: The value of the X-Frame-Options header to be analyzed.
    :type header_value: str

    :return: A list of warning messages if the value is not 'DENY' or 'SAMEORIGIN'. Otherwise, an empty list.
    :rtype: list[str]
    """
    if header_value not in ["DENY", "SAMEORIGIN"]:
        return [f"Valor não recomendado ({header_value}). Deve ser 'DENY' ou 'SAMEORIGIN'."]
    return []

def analyze_x_content_type_options(header_value):
    """
    Analyzes the value of the 'X-Content-Type-Options' header.

    Args:
        header_value (str): The value of the 'X-Content-Type-Options' header.

    Returns:
        list: List of possible recommendations or an empty list if the header value is 'nosniff'.

    Example:
        >>> analyze_x_content_type_options("nosniff")
        []

        >>> analyze_x_content_type_options("other")
        ["Valor não recomendado (other). Deve ser 'nosniff'."]
    """
    if header_value != "nosniff":
        return [f"Valor não recomendado ({header_value}). Deve ser 'nosniff'."]
    return []

def analyze_x_xss_protection(header_value):
    """
    Analyzes the X-XSS-Protection header value.

    This method checks if the provided header value is "1; mode=block". If it is not, it returns an error message indicating that the value is not recommended.

    Parameters:
    header_value (str): The value of the X-XSS-Protection header to be analyzed.

    Returns:
    list: A list containing error messages if the header value is not recommended. If the header value is "1; mode=block", an empty list is returned.

    """
    if header_value != "1; mode=block":
        return [f"Valor não recomendado ({header_value}). Deve ser '1; mode=block'."]
    return []

def industry_benchmark(headers):
    """
    Checks the given HTTP headers against a list of recommended headers commonly used in the industry.

    Args:
        headers (list): A list of HTTP headers to be checked.

    Returns:
        list: A list of recommended headers missing from the given headers.

    Example:
        >>> headers = ['Content-Security-Policy', 'X-Frame-Options', 'Referrer-Policy']
        >>> industry_benchmark(headers)
        ['Strict-Transport-Security', 'X-Content-Type-Options', 'Permissions-Policy']
    """
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
    """
    Get the IP address of a given URL.

    Parameters:
    url (str): The URL for which to retrieve the IP address.

    Returns:
    str: The IP address corresponding to the given URL.

    Raises:
    socket.error: If the IP address for the given URL cannot be found.

    Example:
    >>> get_ip_address('https://www.example.com')
    '93.184.216.34'
    >>> get_ip_address('https://www.invalidurl.com')
    'IP não encontrado'
    """
    try:
        return socket.gethostbyname(url.split('//')[-1].split('/')[0])
    except socket.error:
        return "IP não encontrado"

def calculate_security_grade(missing_count):
    """
    Calculate the security grade based on the number of missing items.

    :param missing_count: The number of missing items (int).
    :return: The security grade (str).
    """
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
    """
    Returns a message based on the security grade.

    Args:
        grade (str): The security grade.

    Returns:
        str: The message based on the security grade.
    """
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
    """
    Check security headers of a given URL.

    Parameters:
    - headers (dict): A dictionary containing the headers of the URL.
    - url (str): The URL to analyze.

    Returns:
    - report (dict): A dictionary containing the security report summary, site information, headers analysis, and raw headers.

    """
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
    """

    The `analyze_cookies` method analyzes the headers provided to it and returns a dictionary with information about the cookies and any potential issues found.

    Parameters:
    - `headers` (dict): A dictionary containing the headers to be analyzed.

    Returns:
    - `results` (dict): A dictionary with the following keys:
        - `'cookies'` (list): A list of dictionaries, each representing a cookie found in the headers. Each cookie dictionary contains key-value pairs representing the various attributes of the cookie.
        - `'issues'` (list): A list of strings, each representing a potential issue found with a cookie.

    Example Usage:
    ```
    headers = {
        'Set-Cookie': 'cookie1=value1; HttpOnly, cookie2=value2; Secure, cookie3=value3; SameSite=Lax'
    }
    analysis = analyze_cookies(headers)
    print(analysis)
    ```

    Output:
    ```
    {
        'cookies': [
            {'cookie1': 'value1', 'httponly': True},
            {'cookie2': 'value2', 'secure': True},
            {'cookie3': 'value3', 'samesite': 'Lax'}
        ],
        'issues': [
            'Aviso: Cookie sem flag HttpOnly.',
            'Aviso: Cookie sem flag Secure.'
        ]
    }
    ```
    """
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
