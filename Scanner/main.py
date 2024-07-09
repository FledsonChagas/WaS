from lib.http_requests import fetch_url
from lib.security_headers import check_security_headers, analyze_cookies
from lib.directory_enumeration import directory_enumeration
from lib.injection_tests import test_sqli
from lib.content_analysis import analyze_content
from lib.authentication_tests import test_authentication
from lib.performance_tests import performance_test_menu
from lib.subdomain_discovery import run_subdomain_discovery
import json


def display_logo():
    """Displays the logo and title of the web asset scanner.

    This method prints the logo and title of the web asset scanner on the console.

    Example:
        The following code demonstrates the usage of this method:

        display_logo()

    Output:
        The method will print the logo and title of the web asset scanner on the console.

    """
    logo = """

   ▄████████  ▄█     ▄█   ▄█▄  ▄█          ▄████████    ▄████████  ▄████████  ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███ ▄███▀ ███         ███    ███   ███    ███ ███    ███ ███▀▀▀▀██▄ ███   ██▄
  ███    ███ ███▌   ███▐██▀   ███▌        ███    ███   ███    █▀  ███    █▀  ███    ███ ███   ███ 
 ▄███▄▄▄▄██▀ ███▌  ▄█████▀    ███▌       ▄███▄▄▄▄██▀  ▄███▄▄▄     ███        ███    ███ ███   ███ 
▀▀███▀▀▀▀▀   ███▌ ▀▀█████▄    ███▌      ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███        ███    ███ ███   ███ 
▀███████████ ███    ███▐██▄   ███       ▀███████████   ███    █▄  ███    █▄  ███    ███ ███   ███ 
  ███    ███ ███    ███ ▀███▄ ███         ███    ███   ███    ███ ███    ███ ███    ███ ███   ███ 
  ███    ███ █▀     ███   ▀█▀ █▀          ███    ███   ██████████ ████████▀   ▀██████▀   ▀█   █▀  
  ███    ███        ▀                     ███    ███                                              
                                                                                         by M4G0"""
    print(logo)
    print("                               Web Asset Scanner")
    print("\n                         Silencioso, Letal e Furtivo\n")


def menu():
    """
    Display menu options for the user to select from and prompt for their choice.

    Returns:
        str: The user's choice from the menu options.
    """
    print("\nSelecione uma função para executar:\n")
    print("1. Verificar cabeçalhos de segurança")
    print("2. Analisar cookies")
    print("3. Enumerar diretórios")
    print("4. Testar SQL Injection")
    print("5. Analisar conteúdo")
    print("6. Testar autenticação")
    print("7. Teste de performance")
    print("8. Descobrir subdomínios")
    print("9. Executar todos os testes")
    print("10. Sair\n")
    choice = input("Selecione uma opção do menu: ")
    return choice


def execute_choice(choice, url, response):
    """
    Executes a specific choice based on the given input.

    Parameters:
    choice (str): The choice selected by the user.
    url (str): The URL to be analyzed.
    response (object): The response object received from the HTTP request.

    Returns:
    bool: True if the function is successful and should continue running, False otherwise.
    """
    if choice == '1':
        result = check_security_headers(response.headers, url)
        print(json.dumps(result, indent=4, ensure_ascii=False))
    elif choice == '2':
        result = analyze_cookies(response.headers)
        print(json.dumps(result, indent=4, ensure_ascii=False))
    elif choice == '3':
        directory_enumeration(url)
    elif choice == '4':
        test_sqli(url)
    elif choice == '5':
        analyze_content(response.text)
    elif choice == '6':
        test_authentication(url)
    elif choice == '7':
        performance_test_menu(url)
    elif choice == '8':
        run_subdomain_discovery(url)
    elif choice == '9':
        result_headers = check_security_headers(response.headers)
        result_cookies = analyze_cookies(response.headers)
        print(json.dumps({"security_headers": result_headers, "cookies": result_cookies}, indent=4, ensure_ascii=False))
        directory_enumeration(url)
        test_sqli(url)
        analyze_content(response.text)
        test_authentication(url)
        performance_test_menu(url)
        run_subdomain_discovery(url)
    elif choice == '10':
        return False
    else:
        print("Escolha inválida, por favor selecione novamente.")
    return True


def main(url):
    """
    Main method that handles the execution of the program.

    Parameters:
    - url (str): The URL to be scanned.

    Returns:
    None
    """
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
