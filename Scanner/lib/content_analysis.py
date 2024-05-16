from bs4 import BeautifulSoup, Comment

def analyze_content(html):
    soup = BeautifulSoup(html, 'html.parser')
    comments = soup.findAll(text=lambda text: isinstance(text, Comment))
    print("Comentários encontrados no HTML:")
    for comment in comments:
        print(comment)
