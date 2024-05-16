import threading
from .http_requests import fetch_url

def stress_test(url, num_requests):
    def make_request():
        resp = fetch_url(url)
        if resp:
            print(f"Status: {resp.status_code}")

    threads = []
    for _ in range(num_requests):
        t = threading.Thread(target=make_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
