from lib.http_requests import fetch_url
from lib.security_headers import check_security_headers, analyze_cookies
from lib.directory_enumeration import directory_enumeration
from lib.injection_tests import test_sqli
from lib.content_analysis import analyze_content
from lib.authentication_tests import test_authentication
from lib.performance_tests import stress_test

def main(url):
    response = fetch_url(url)
    if response:
        check_security_headers(response.headers)
        analyze_cookies(response.headers)
        directory_enumeration(url)
        test_sqli(url)
        analyze_content(response.text)
        test_authentication(url)
        stress_test(url, 100)

if __name__ == "__main__":
    url = input("Digite a URL para scanear: ")
    main(url)
