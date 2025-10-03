"""
Programa de Descriptografia de Árvores Binárias
================================================

Este programa permite ao usuário selecionar arquivos JSON criptografados, chaves privadas e públicas,
descriptografar o conteúdo usando criptografia híbrida (RSA + AES-GCM), reconstruir a árvore binária
a partir dos metadados pós-ordem e exibir a mensagem original decodificada de valores binários ASCII.

Requisitos:
- cryptography: Para operações criptográficas.
- graphviz: Para visualização gráfica da árvore.
- Pillow: Para manipulação de imagens.

Autor: [Seu Nome ou Equipe]
Data: 03 de Outubro de 2025
Versão: 1.5 (Correção de Timing do GIF)
"""

import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from graphviz import Digraph
from PIL import Image, ImageTk, ImageSequence
import time

# Classe para representar um nó da árvore binária
class Node:
    def __init__(self, value, left=-1, right=-1):
        """
        Inicializa um nó da árvore.
        - value: Valor do nó (binário ou None).
        - left: Índice do filho esquerdo.
        - right: Índice do filho direito.
        """
        self.value = value
        self.left = left
        self.right = right

# Função para descriptografar o arquivo JSON
def decrypt_data(json_path, private_key_path):
    """
    Descriptografa o conteúdo do JSON usando RSA-OAEP e AES-GCM.
    Retorna os dados desserializados ou uma mensagem de erro.
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)

        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Adicione senha se necessário: b'sua_senha'
                backend=default_backend()
            )

        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext_with_tag = base64.b64decode(encrypted_data['ciphertext'])

        if len(ciphertext_with_tag) < 16:
            raise ValueError("Ciphertext muito curto, tag de autenticação ausente.")

        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return json.loads(plaintext.decode('utf-8', errors='ignore'))
    except Exception as e:
        return str(e)

# Função para reconstruir a árvore a partir de tree_meta
def build_tree(tree_meta):
    """
    Constrói uma lista de nós da árvore com base nos metadados.
    """
    return [Node(meta["val"], meta["left"], meta["right"]) for meta in tree_meta]

# Função para gerar o gráfico da árvore usando Graphviz
def create_tree_graph(nodes):
    """
    Cria um gráfico da árvore binária em formato Digraph.
    """
    dot = Digraph(comment='Árvore Binária')
    for i, node in enumerate(nodes):
        if node.value is not None:
            dot.node(str(i), label=f"{i}: {node.value}")
        if node.left != -1:
            dot.edge(str(i), str(node.left))
        if node.right != -1:
            dot.edge(str(i), str(node.right))
    return dot

# Função para extrair a mensagem decodificada
def extract_message(postorder_list, original_length):
    """
    Converte os valores binários em caracteres ASCII.
    """
    binary_values = [x for x in postorder_list if x is not None][:original_length]
    return ''.join(chr(int(binary, 2)) for binary in binary_values)

# Interface Gráfica
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Descriptografia de Árvore Binária")
        
        # Guardando a geometria inicial para o primeiro redimensionamento
        self.initial_width, self.initial_height = 600, 550
        self.geometry(f"{self.initial_width}x{self.initial_height}")
        
        self.json_path = None
        self.private_key_path = None
        self.public_key_path = None
        self.darth_image = None
        self.darth_label = None

        # Variáveis para o redimensionamento dinâmico
        self.original_gif_frames = [] 
        self.bg_frames = [] # É importante inicializar a lista aqui
        self._resize_job = None

        # Carregar e animar o GIF de fundo
        try:
            self.bg_label = tk.Label(self)
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)

            gif_path = "fundo.gif"
            self.bg_gif = Image.open(gif_path)
            
            self.original_gif_frames = [frame.copy() for frame in ImageSequence.Iterator(self.bg_gif)]
            
            # --- CORREÇÃO APLICADA AQUI ---
            # Realiza o primeiro redimensionamento antes de iniciar a animação
            self.bg_frames = [
                ImageTk.PhotoImage(frame.resize((self.initial_width, self.initial_height), Image.Resampling.LANCZOS))
                for frame in self.original_gif_frames
            ]
            # --- FIM DA CORREÇÃO ---

            self.bind("<Configure>", self.on_resize)
            self.animate_bg(0)

        except Exception as e:
            self.configure(bg='#001F3F')
            print(f"Erro ao carregar GIF: {e}")

        # Configuração de estilos
        style = ttk.Style()
        style.configure("TLabel", foreground="white", background="#000000", font=("Arial", 10))
        style.configure("TButton", background="#000000", foreground="white", font=("Arial", 10))
        style.map("TButton", background=[('active', "#000000")], relief=[('pressed', 'flat')])

        # Componentes da interface
        self.label_json = ttk.Label(self, text="Arquivo JSON:")
        self.label_json.pack(pady=10)
        self.btn_json = ttk.Button(self, text="Selecionar JSON", command=self.select_json)
        self.btn_json.pack(pady=5)

        self.label_private = ttk.Label(self, text="Chave Privada:")
        self.label_private.pack(pady=10)
        self.btn_private = ttk.Button(self, text="Selecionar Chave Privada", command=self.select_private)
        self.btn_private.pack(pady=5)

        self.label_public = ttk.Label(self, text="Chave Pública (opcional):")
        self.label_public.pack(pady=10)
        self.btn_public = ttk.Button(self, text="Selecionar Chave Pública", command=self.select_public)
        self.btn_public.pack(pady=5)

        self.btn_decrypt = ttk.Button(self, text="Descriptografar e Gerar Árvore", command=self.perform_decrypt)
        self.btn_decrypt.pack(pady=20)

        self.result_text = tk.Text(self, height=8, width=50, bg="#000000", fg='white', wrap=tk.WORD, font=("Arial", 10))
        self.result_text.pack(pady=10)

    def on_resize(self, event):
        if self._resize_job:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(150, self.resize_background)

    def resize_background(self):
        new_width = self.winfo_width()
        new_height = self.winfo_height()

        if new_width < 2 or new_height < 2:
            return

        self.bg_frames = [
            ImageTk.PhotoImage(frame.resize((new_width, new_height), Image.Resampling.LANCZOS))
            for frame in self.original_gif_frames
        ]

    def animate_bg(self, frame_num):
        if self.bg_frames:
            current_frame_index = frame_num % len(self.bg_frames)
            frame_image = self.bg_frames[current_frame_index]
            self.bg_label.config(image=frame_image)
            
            # Garante que a referência à imagem seja mantida
            self.bg_label.image = frame_image
            
            next_frame_index = (current_frame_index + 1)
            self.after(100, self.animate_bg, next_frame_index)

    def select_json(self):
        self.json_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        self.label_json.config(text=f"Arquivo JSON: {self.json_path or 'Não selecionado'}")

    def select_private(self):
        self.private_key_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        self.label_private.config(text=f"Chave Privada: {self.private_key_path or 'Não selecionado'}")

    def select_public(self):
        self.public_key_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        self.label_public.config(text=f"Chave Pública: {self.public_key_path or 'Não selecionado'}")

    def perform_decrypt(self):
        if not self.json_path or not self.private_key_path:
            messagebox.showerror("Erro", "Selecione o arquivo JSON e a chave privada!")
            return

        decrypted_data = decrypt_data(self.json_path, self.private_key_path)

        if isinstance(decrypted_data, str):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Erro: {decrypted_data}\n")
            return

        try:
            tree = build_tree(decrypted_data["tree_meta"])
            tree_graph = create_tree_graph(tree)
            output_file = 'tree_graph.png'
            tree_graph.render(output_file, view=True, format='png')

            message = extract_message(decrypted_data["postorder_list"], decrypted_data["original_length"])

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Descriptografia concluída com sucesso!\n")
            self.result_text.insert(tk.END, "Árvore gerada como 'tree_graph.png' e aberta automaticamente.\n")

            self.show_message_window(message)
            self.show_darth_image()
        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Erro ao processar dados: {e}\n")

    def show_message_window(self, message):
        msg_window = tk.Toplevel(self)
        msg_window.title("Mensagem Descriptografada")
        msg_window.geometry("400x150")
        msg_window.configure(bg="#000000")

        msg_label = ttk.Label(msg_window, text=f"Mensagem: {message}", wraplength=380, justify="left", font=("Arial", 12))
        msg_label.pack(pady=20)

        close_button = ttk.Button(msg_window, text="Fechar", command=msg_window.destroy)
        close_button.pack(pady=10)

    def show_darth_image(self):
        try:
            darth_img = Image.open("Vader.jpg")
            darth_img = darth_img.resize((150, 150), Image.Resampling.LANCZOS)
            self.darth_image = ImageTk.PhotoImage(darth_img)
            
            if self.darth_label is None:
                self.darth_label = tk.Label(self, image=self.darth_image, bg='#001F3F')
                self.darth_label.pack(pady=5)
            else:
                self.darth_label.config(image=self.darth_image)

            self.darth_label.image = self.darth_image
            
        except Exception as e:
            self.result_text.insert(tk.END, f"Erro ao carregar imagem: {e}\n")

if __name__ == "__main__":
    app = App()
    app.mainloop()