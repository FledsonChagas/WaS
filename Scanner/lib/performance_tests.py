# scanner/lib/performance_tests.py

import threading
import time
import sys
import json
from .http_requests import fetch_url
from tqdm import tqdm


def calculate_statistics(times):
    return {
        "average": sum(times) / len(times) if times else 0,
        "max": max(times) if times else 0,
        "min": min(times) if times else 0,
        "median": sorted(times)[len(times) // 2] if times else 0,
        "percentile_90": sorted(times)[int(len(times) * 0.9)] if times else 0,
        "percentile_95": sorted(times)[int(len(times) * 0.95)] if times else 0,
        "percentile_99": sorted(times)[int(len(times) * 0.99)] if times else 0,
    }


def stress_test(url, num_requests, num_threads, interval_ms, duration=None):
    results = {
        "success": 0,
        "failure": 0,
        "error_messages": [],
        "response_times": [],
    }

    def make_request():
        try:
            start_time = time.time()
            resp = fetch_url(url)
            elapsed_time = time.time() - start_time
            results["response_times"].append(elapsed_time)
            if resp and resp.status_code == 200:
                results["success"] += 1
            else:
                results["failure"] += 1
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

    with tqdm(total=num_requests, desc="Executing requests") as progress:
        for _ in range(num_threads):
            t = threading.Thread(target=worker, args=(progress,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    response_time_stats = calculate_statistics(results["response_times"])
    return results, response_time_stats


def load_test(url, num_requests, interval_ms):
    results = {
        "success": 0,
        "failure": 0,
        "error_messages": [],
        "response_times": [],
    }

    def make_request():
        try:
            start_time = time.time()
            resp = fetch_url(url)
            elapsed_time = time.time() - start_time
            results["response_times"].append(elapsed_time)
            if resp and resp.status_code == 200:
                results["success"] += 1
            else:
                results["failure"] += 1
        except Exception as e:
            results["error_messages"].append(str(e))
            results["failure"] += 1

    with tqdm(total=num_requests, desc="Executing load test requests") as progress:
        for _ in range(num_requests):
            make_request()
            time.sleep(interval_ms / 1000.0)
            progress.update(1)

    response_time_stats = calculate_statistics(results["response_times"])
    return results, response_time_stats


def dos_test(url, num_requests, interval_ms):
    results = {
        "success": 0,
        "failure": 0,
        "error_messages": [],
        "response_times": [],
    }

    def make_request():
        try:
            start_time = time.time()
            resp = fetch_url(url)
            elapsed_time = time.time() - start_time
            results["response_times"].append(elapsed_time)
            if resp and resp.status_code == 200:
                results["success"] += 1
            else:
                results["failure"] += 1
        except Exception as e:
            results["error_messages"].append(str(e))
            results["failure"] += 1

    with tqdm(total=num_requests, desc="Executing DoS requests") as progress:
        for _ in range(num_requests):
            make_request()
            time.sleep(interval_ms / 1000.0)
            progress.update(1)

    response_time_stats = calculate_statistics(results["response_times"])
    return results, response_time_stats


def performance_test_menu(url):
    while True:
        print("\nSelecione um tipo de teste de performance:\n")
        print("1. Teste de Carga")
        print("2. Teste de Estresse")
        print("3. Simulação de DoS")
        print("4. Teste de Limite Gradual")
        print("5. Voltar ao menu principal\n")
        choice = input("Selecione uma opção do menu: ")

        if choice == '1':
            run_load_test(url)
        elif choice == '2':
            run_stress_test(url)
        elif choice == '3':
            run_dos_test(url)
        elif choice == '4':
            run_gradual_stress_test(url)
        elif choice == '5':
            return
        else:
            print("Opção inválida. Por favor, tente novamente.")


def run_stress_test(url):
    num_requests = int(input("Número total de requisições: "))
    num_threads = int(input("Número de threads: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))
    duration = input("Duração do teste (s, opcional): ")
    duration = int(duration) if duration else None

    results, response_time_stats = stress_test(url, num_requests, num_threads, interval_ms, duration)
    print_results(results, response_time_stats)

    post_test_menu(url)


def run_load_test(url):
    num_requests = int(input("Número total de requisições: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))

    results, response_time_stats = load_test(url, num_requests, interval_ms)
    print_results(results, response_time_stats)

    post_test_menu(url)


def run_dos_test(url):
    num_requests = int(input("Número total de requisições: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))

    results, response_time_stats = dos_test(url, num_requests, interval_ms)
    print_results(results, response_time_stats)

    post_test_menu(url)


def run_gradual_stress_test(url):
    initial_requests = int(input("Número inicial de requisições: "))
    increment = int(input("Incremento de requisições a cada etapa: "))
    max_requests = int(input("Número máximo de requisições: "))
    interval_ms = int(input("Intervalo entre requisições (ms): "))
    duration = input("Duração de cada etapa (s, opcional): ")
    duration = int(duration) if duration else None

    results, response_time_stats = gradual_stress_test(url, initial_requests, increment, max_requests, interval_ms, duration)
    print_results(results, response_time_stats)

    post_test_menu(url)


def print_results(results, response_time_stats):
    total_requests = results["success"] + results["failure"]
    success_rate = (results["success"] / total_requests) * 100 if total_requests else 0
    failure_rate = (results["failure"] / total_requests) * 100 if total_requests else 0

    summary = {
        "total_requests": total_requests,
        "successful_requests": results['success'],
        "failed_requests": results['failure'],
        "success_rate": success_rate,
        "failure_rate": failure_rate,
        "error_messages": results['error_messages'],
        "response_time_statistics": {
            "average_response_time": response_time_stats['average'],
            "max_response_time": response_time_stats['max'],
            "min_response_time": response_time_stats['min'],
            "median_response_time": response_time_stats['median'],
            "90th_percentile_response_time": response_time_stats['percentile_90'],
            "95th_percentile_response_time": response_time_stats['percentile_95'],
            "99th_percentile_response_time": response_time_stats['percentile_99'],
        }
    }

    print("\n--- Test Results Summary ---")
    print(json.dumps(summary, indent=4))

    print("\n--- Test Results JSON ---")
    print(json.dumps(results, indent=4))


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
            print("Escolha inválida. Por favor, tente novamente.")
