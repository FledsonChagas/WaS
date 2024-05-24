# scanner/lib/performance_tests.py

import threading
import time
import sys
from .http_requests import fetch_url


def stress_test(url, num_requests, num_threads, interval_ms, duration=None):
    results = {
        "success": 0,
        "failure": 0,
        "error_messages": [],
    }

    def make_request():
        try:
            start_time = time.time()
            resp = fetch_url(url)
            if resp and resp.status_code == 200:
                results["success"] += 1
            else:
                results["failure"] += 1
            elapsed_time = time.time() - start_time
        except Exception as e:
            results["error_messages"].append(str(e))
            results["failure"] += 1

    def worker(progress):
        requests_per_thread = num_requests // num_threads
        for _ in range(requests_per_thread):
            if duration and time.time() - start_time >= duration:
                break
            make_request()
            time.sleep(interval_ms / 1000.0)
            progress.update(1)

    threads = []
    start_time = time.time()

    with Progress(total=num_requests, desc="Executing requests") as progress:
        for _ in range(num_threads):
            t = threading.Thread(target=worker, args=(progress,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    return results


def load_test(url, num_requests, interval_ms):
    results = {
        "success": 0,
        "failure": 0,
        "error_messages": [],
    }

    def make_request():
        try:
            resp = fetch_url(url)
            if resp and resp.status_code == 200:
                results["success"] += 1
            else:
                results["failure"] += 1
        except Exception as e:
            results["error_messages"].append(str(e))
            results["failure"] += 1

    with Progress(total=num_requests, desc="Executing load test requests") as progress:
        for _ in range(num_requests):
            make_request()
            time.sleep(interval_ms / 1000.0)
            progress.update(1)

    return results


def dos_test(url, num_requests, interval_ms):
    results = {
        "success": 0,
        "failure": 0,
        "error_messages": [],
    }

    def make_request():
        try:
            resp = fetch_url(url)
            if resp and resp.status_code == 200:
                results["success"] += 1
            else:
                results["failure"] += 1
        except Exception as e:
            results["error_messages"].append(str(e))
            results["failure"] += 1

    with Progress(total=num_requests, desc="Executing DoS requests") as progress:
        for _ in range(num_requests):
            make_request()
            time.sleep(interval_ms / 1000.0)
            progress.update(1)

    return results


def performance_test_menu(url):
    while True:
        print("\nSelecione um tipo de teste de performance:\n")
        print("1. Teste de Carga")
        print("2. Teste de Estresse")
        print("3. Simulação de DoS")
        print("4. Voltar ao menu principal\n")
        choice = input("Selecione uma opção do menu: ")

        if choice == '1':
            run_load_test(url)
        elif choice == '2':
            run_stress_test(url)
        elif choice == '3':
            run_dos_test(url)
        elif choice == '4':
            return
        else:
            print("Opção inválida. Por favor, tente novamente.")


def run_stress_test(url):
    num_requests = int(input("Número total de requisições: "))
    num_threads = int(input("Número de threads: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))
    duration = input("Duração do teste (s, opcional): ")
    duration = int(duration) if duration else None

    results = stress_test(url, num_requests, num_threads, interval_ms, duration)
    print(f"Test Results: {results}")

    post_test_menu(url)


def run_load_test(url):
    num_requests = int(input("Número total de requisições: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))

    results = load_test(url, num_requests, interval_ms)
    print(f"Test Results: {results}")

    post_test_menu(url)


def run_dos_test(url):
    num_requests = int(input("Número total de requisições: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))

    results = dos_test(url, num_requests, interval_ms)
    print(f"Test Results: {results}")

    post_test_menu(url)


def post_test_menu(url):
    while True:
        print("\nDeseja realizar outra ação?")
        print("1. Refazer o teste com a URL atual")
        print("2. Refazer o teste com outra URL")
        print("3. Voltar ao menu inicial")
        print("4. Sair")
        choice = input("Digite o número da sua escolha: ")

        if choice == '1':
            performance_test_menu(url)
        elif choice == '2':
            url = input("Digite a nova URL para scanear: ")
            response = fetch_url(url)
            if not response:
                print("Falha ao conectar com a URL fornecida. Por favor, tente novamente.")
                return
            performance_test_menu(url)
        elif choice == '3':
            return
        elif choice == '4':
            sys.exit()
        else:
            print("Escolha inválida, por favor, tente novamente.")
