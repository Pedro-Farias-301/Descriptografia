# Programa de Descriptografia de Árvores Binárias

Aplicação gráfica desenvolvida em Python para descriptografar mensagens ocultas em metadados de árvores binárias, utilizando um sistema de criptografia híbrida (RSA + AES-GCM).

## Descrição

Este projeto é uma ferramenta de descriptografia com uma interface gráfica construída em Tkinter. Ele é projetado para ler um arquivo `.json` específico, que contém uma mensagem criptografada e metadados de uma árvore binária. O programa utiliza uma chave privada RSA para descriptografar uma chave de sessão AES, que por sua vez é usada para descriptografar o conteúdo principal.

Após a descriptografia, o programa:

1.  Reconstrói a árvore binária a partir dos metadados.
2.  Gera uma visualização gráfica da árvore usando o **Graphviz**.
3.  Decodifica a mensagem original a partir de uma lista de valores binários (ASCII).
4.  Exibe a mensagem final para o usuário.

A interface conta com um fundo animado (GIF) que se adapta dinamicamente ao tamanho da janela.

## Funcionalidades

  - **Interface Gráfica Intuitiva**: Facilita a seleção de arquivos e o processo de descriptografia.
  - **Criptografia Híbrida**: Segurança garantida pelo uso de RSA-OAEP para a troca de chaves e AES-GCM para a cifra dos dados.
  - **Visualização de Árvore**: Geração automática de um arquivo de imagem (`.png`) que mostra a estrutura da árvore binária reconstruída.
  - **Fundo Dinâmico**: O GIF de fundo se redimensiona automaticamente para preencher a janela, mesmo em modo de tela cheia.
  - **Feedback ao Usuário**: Mensagens de status, sucesso e erro são exibidas na interface.

## Pré-requisitos

Antes de instalar e executar o programa, você precisa ter o seguinte instalado em seu sistema:

1.  **Python 3.8 ou superior**.
2.  **pip** (gerenciador de pacotes do Python).
3.  **Graphviz (Software)**: A biblioteca Python `graphviz` é apenas um conector. Você **precisa** instalar o software Graphviz no seu sistema operacional.
      - **Windows**: `choco install graphviz` ou baixe do [site oficial](https://graphviz.org/download/).
      - **macOS**: `brew install graphviz`
      - **Linux (Debian/Ubuntu)**: `sudo apt-get install graphviz`

## Instalação

1.  Clone este repositório ou baixe os arquivos para uma pasta em seu computador.

2.  Navegue até a pasta do projeto pelo terminal.

3.  Crie e ative um ambiente virtual (recomendado):

    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # macOS/Linux
    source venv/bin/activate
    ```

4.  Instale as dependências Python a partir do arquivo `requirements.txt`:

    ```bash
    pip install -r requirements.txt
    ```

    (O conteúdo do `requirements.txt` deve ser: `cryptography`, `graphviz`, `Pillow`)

## Estrutura de Arquivos

Para que o programa funcione corretamente, certifique-se de que a pasta do projeto contenha os seguintes arquivos:

```
.
├── seu_script.py            # O código principal do programa
├── requirements.txt         # Arquivo com as dependências
├── background.gif           # GIF animado para o fundo
├── darth_vader_heart.png    # Imagem que aparece após o sucesso
├── arquivo_criptografado.json # Exemplo de arquivo de entrada
└── sua_chave_privada.pem      # Chave privada RSA para descriptografar
```

## Como Usar

1.  Execute o script principal a partir do seu terminal:
    ```bash
    python seu_script.py
    ```
2.  A janela do programa será aberta.
3.  Clique em **"Selecionar JSON"** e escolha o arquivo `.json` criptografado.
4.  Clique em **"Selecionar Chave Privada"** e escolha sua chave `.pem`.
5.  Clique no botão **"Descriptografar e Gerar Árvore"**.
6.  Se tudo ocorrer bem:
      - Uma imagem da árvore (`tree_graph.png`) será salva na pasta e aberta automaticamente.
      - Uma pequena janela aparecerá com a mensagem descriptografada.
      - A imagem do Darth Vader aparecerá na janela principal.

## Formato do Arquivo JSON de Entrada

O programa espera um arquivo `.json` com a seguinte estrutura:

```json
{
  "encrypted_key": "BASE64_ENCODED_STRING",
  "nonce": "BASE64_ENCODED_STRING",
  "ciphertext": "BASE64_ENCODED_STRING"
}
```

O `ciphertext`, após ser descriptografado com a chave AES, deve resultar em um novo JSON com a seguinte estrutura interna:

```json
{
  "tree_meta": [
    {"val": "BINARY_STRING_OR_NULL", "left": INDEX, "right": INDEX},
    ...
  ],
  "postorder_list": [
    "01001000",
    "01100101",
    "01101100",
    "01101100",
    "01101111"
  ],
  "original_length": 5
}
```

> **IMPORTANTE**: A lista `postorder_list` **deve** conter strings de texto representando números binários de 8 bits (formato `08b`), correspondentes aos códigos ASCII dos caracteres da mensagem original.


## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
