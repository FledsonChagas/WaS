import requests
import json

def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Failed to fetch data from crt.sh")

    subdomains = set()
    for cert in response.json():
        if cert.get('name_value'):
            subdomains.update(cert['name_value'].split('\n'))
    return list(subdomains)

def run_subdomain_discovery(domain):
    subdomains = get_subdomains_from_crtsh(domain)
    output = {
        "domain": domain,
        "found_subdomains": subdomains
    }
    output_json = json.dumps(output, indent=4)
    print(output_json)
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
