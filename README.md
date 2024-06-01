

# Web Asset Scanner

```
   ▄████████  ▄█     ▄█   ▄█▄  ▄█          ▄████████    ▄████████  ▄████████  ▄██████▄  ███▄▄▄▄   
  ███    ███ ███    ███ ▄███▀ ███         ███    ███   ███    ███ ███    ███ ███▀▀▀▀██▄ ███   ██▄
  ███    ███ ███▌   ███▐██▀   ███▌        ███    ███   ███    █▀  ███    █▀  ███    ███ ███   ███ 
 ▄███▄▄▄▄██▀ ███▌  ▄█████▀    ███▌       ▄███▄▄▄▄██▀  ▄███▄▄▄     ███        ███    ███ ███   ███ 
▀▀███▀▀▀▀▀   ███▌ ▀▀█████▄    ███▌      ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███        ███    ███ ███   ███ 
▀███████████ ███    ███▐██▄   ███       ▀███████████   ███    █▄  ███    █▄  ███    ███ ███   ███ 
  ███    ███ ███    ███ ▀███▄ ███         ███    ███   ███    ███ ███    ███ ███    ███ ███   ███ 
  ███    ███ █▀     ███   ▀█▀ █▀          ███    ███   ██████████ ████████▀   ▀██████▀   ▀█   █▀  
  ███    ███        ▀                     ███    ███                                              
                                                                                         by M4G0
```

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Menu Options](#menu-options)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Introduction

The Web Asset Scanner is a comprehensive tool for performing security and performance assessments on web assets. It offers various functionalities like checking security headers, analyzing cookies, enumerating directories, testing for SQL injection, and more. This tool is designed to be both user-friendly and powerful, catering to the needs of security professionals and enthusiasts alike.

## Features

- **Security Headers Check**: Analyze the security headers of a given URL.
- **Cookie Analysis**: Examine the cookies set by the web server.
- **Directory Enumeration**: Discover directories on the web server.
- **SQL Injection Testing**: Test for SQL injection vulnerabilities.
- **Content Analysis**: Analyze the content of the web page.
- **Authentication Tests**: Test the authentication mechanisms of the web server.
- **Performance Tests**: Perform various performance tests on the web server.
- **Subdomain Discovery**: Discover subdomains associated with the web server.
- **Comprehensive Scanning**: Run all tests with a single command.

## Installation

To install the Web Asset Scanner, you need to have Python installed on your machine. Follow the steps below to get started:

1. Clone the repository:
    ```sh
    git clone https://github.com/your-username/web-asset-scanner.git
    cd web-asset-scanner
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

To use the Web Asset Scanner, run the following command:
```sh
python main.py
```
You will be prompted to enter a URL to scan, and then you can select various options from the menu to perform different tests.

## Menu Options

The tool provides the following menu options:

1. **Verificar cabeçalhos de segurança**: Check the security headers of the provided URL.
2. **Analisar cookies**: Analyze the cookies set by the web server.
3. **Enumerar diretórios**: Enumerate directories on the web server.
4. **Testar SQL Injection**: Test for SQL injection vulnerabilities.
5. **Analisar conteúdo**: Analyze the content of the web page.
6. **Testar autenticação**: Test the authentication mechanisms of the web server.
7. **Teste de performance**: Perform performance tests on the web server.
8. **Descobrir subdomínios**: Discover subdomains associated with the web server.
9. **Executar todos os testes**: Run all available tests.
10. **Sair**: Exit the program.

## Project Structure

```
scanner/
│
├── lib/
│   ├── __init__.py
│   ├── http_requests.py
│   ├── security_headers.py
│   ├── directory_enumeration.py
│   ├── injection_tests.py
│   ├── content_analysis.py
│   ├── authentication_tests.py
│   ├── performance_tests.py
│   ├── subdomain_discovery.py       # New
│   └── seclists/
│       └── Discovery/
│           └── Web-Content/
│               └── common.txt
│
└── main.py
```

## Contributing

We welcome contributions to improve the Web Asset Scanner. If you have any ideas, suggestions, or bug reports, feel free to open an issue or submit a pull request. Please ensure your contributions adhere to the project's coding standards and guidelines.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

Happy scanning!

By M4G0
