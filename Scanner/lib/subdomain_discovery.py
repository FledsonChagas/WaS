import requests
import json
from tqdm import tqdm
import sys

def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to fetch data from crt.sh")

    subdomains = set()
    try:
        data = response.json()
    except json.JSONDecodeError:
        print("Failed to decode JSON response from crt.sh")
        return []

    print(f"Total certificates found: {len(data)}")  # Depuração: Número total de certificados encontrados

    progress_bar = tqdm(total=len(data), desc="Processing subdomains")
    for cert in data:
        if 'name_value' in cert:
            subdomains.update(cert['name_value'].split('\n'))
        progress_bar.update(1)
    progress_bar.close()

    subdomains = list(filter(None, subdomains))
    print(f"Total unique subdomains found: {len(subdomains)}")  # Depuração: Número total de subdomínios únicos
    return subdomains

def run_subdomain_discovery(domain):
    subdomains = get_subdomains_from_crtsh(domain)
    output = {
        "domain": domain,
        "found_subdomains": subdomains
    }
    output_json = json.dumps(output, indent=4, ensure_ascii=False)
    print(output_json)
    print(f"\nTotal subdomains found: {len(subdomains)}")  # Exibir o total de subdomínios encontrados
    post_test_menu(domain)

def post_test_menu(url):
    while True:
        print("\nDeseja realizar outra ação?")
        print("1. Refazer o teste com a URL atual")
        print("2. Refazer o teste com outra URL")
        print("3. Voltar ao menu inicial")
        print("4. Sair")
        choice = input("Digite o número da sua escolha: ")

        if choice == '1':
            run_subdomain_discovery(url)
        elif choice == '2':
            url = input("Digite a nova URL para scanear: ")
            run_subdomain_discovery(url)
        elif choice == '3':
            return
        elif choice == '4':
            sys.exit()
        else:
            print("Escolha inválida, por favor, tente novamente.")

# Testando a função com um domínio de exemplo
if __name__ == "__main__":
    domain = input("Digite o domínio para descobrir subdomínios: ")
    run_subdomain_discovery(domain)
