from lib.http_requests import fetch_url
from lib.security_headers import check_security_headers, analyze_cookies
from lib.directory_enumeration import directory_enumeration
from lib.injection_tests import test_sqli
from lib.content_analysis import analyze_content
from lib.authentication_tests import test_authentication
from lib.performance_tests import stress_test

def display_logo():
    logo = """
   ▄████████  ▄█     ▄█   ▄█▄  ▄█          ▄████████    ▄████████  ▄████████  ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███ ▄███▀ ███         ███    ███   ███    ███ ███    ███ ███    ███ ███▀▀▀██▄ 
  ███    ███ ███▌   ███▐██▀   ███▌        ███    ███   ███    █▀  ███    █▀  ███    ███ ███   ███ 
 ▄███▄▄▄▄██▀ ███▌  ▄█████▀    ███▌       ▄███▄▄▄▄██▀  ▄███▄▄▄     ███        ███    ███ ███   ███ 
▀▀███▀▀▀▀▀   ███▌ ▀▀█████▄    ███▌      ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███        ███    ███ ███   ███ 
▀███████████ ███    ███▐██▄   ███       ▀███████████   ███    █▄  ███    █▄  ███    ███ ███   ███ 
  ███    ███ ███    ███ ▀███▄ ███         ███    ███   ███    ███ ███    ███ ███    ███ ███   ███ 
  ███    ███ █▀     ███   ▀█▀ █▀          ███    ███   ██████████ ████████▀   ▀██████▀   ▀█   █▀  
  ███    ███        ▀                     ███    ███                                              
    """
    print(logo)
    print("                          Web Asset Scanner")
    print("\n                      Silencioso, Letal e Furtivo\n")

def menu():
    print("\nSelecione uma função para executar:\n")
    print("1. Verificar cabeçalhos de segurança")
    print("2. Analisar cookies")
    print("3. Enumerar diretórios")
    print("4. Testar SQL Injection")
    print("5. Analisar conteúdo")
    print("6. Testar autenticação")
    print("7. Teste de estresse")
    print("8. Executar todos os testes")
    print("9. Sair\n")
    choice = input("Selecione uma opção do menu: ")
    return choice

def execute_choice(choice, url, response):
    if choice == '1':
        check_security_headers(response.headers)
    elif choice == '2':
        analyze_cookies(response.headers)
    elif choice == '3':
        directory_enumeration(url)
    elif choice == '4':
        test_sqli(url)
    elif choice == '5':
        analyze_content(response.text)
    elif choice == '6':
        test_authentication(url)
    elif choice == '7':
        stress_test(url, 100)
    elif choice == '8':
        check_security_headers(response.headers)
        analyze_cookies(response.headers)
        directory_enumeration(url)
        test_sqli(url)
        analyze_content(response.text)
        test_authentication(url)
        stress_test(url, 100)
    elif choice == '9':
        return False
    else:
        print("Escolha inválida, por favor selecione novamente.")
    return True

def main(url):
    response = fetch_url(url)
    if not response:
        print("Falha ao conectar com a URL fornecida. Por favor, tente novamente.")
        return

    last_choice = None

    while True:
        if last_choice is None:
            choice = menu()
        else:
            choice = last_choice

        if not execute_choice(choice, url, response):
            break

        print("\nDeseja realizar outra ação?")
        print("1. Refazer o teste com a URL atual")
        print("2. Refazer o teste com outra URL")
        print("3. Voltar ao menu inicial")
        print("4. Sair")
        follow_up_choice = input("Digite o número da sua escolha: ")

        if follow_up_choice == '1':
            last_choice = choice  # Mantém a última escolha para repetir o mesmo teste
            continue
        elif follow_up_choice == '2':
            url = input("Digite a nova URL para scanear: ")
            response = fetch_url(url)
            if not response:
                print("Falha ao conectar com a URL fornecida. Por favor, tente novamente.")
                return
            last_choice = choice  # Mantém a última escolha para repetir o mesmo teste com uma nova URL
        elif follow_up_choice == '3':
            last_choice = None  # Redefine a última escolha para mostrar o menu novamente
        elif follow_up_choice == '4':
            break
        else:
            print("Escolha inválida, saindo do programa.")
            break

if __name__ == "__main__":
    display_logo()
    url = input("Digite a URL para scanear: ")
    main(url)
