"""
Tela.py
Interface Tkinter para o nó EDUCOIN.

Funcionalidades:
- Login / cadastro de usuário (ALUNO / PROFESSOR / DIRETOR)
- Geração de chaves pública e privada a partir de frases
- Crédito inicial: 10 / 100 / 1000 EDU (conforme tipo)
- Consulta de saldo, transferência (com confirmação via chave privada)
- Histórico de transações e visualização da blockchain
- Eleição em anel e mural distribuído
"""
import threading
import json
import os
import uuid
from dataclasses import dataclass, asdict
from typing import List, Optional

import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog

import Funcões as ring  # backend HTTP

USERS_FILE = "usuarios.json"
API_BASE = f"http://127.0.0.1:{ring.PORT}"


# --------------------------------------------------------------------
# Modelo de usuário (GUI)
# --------------------------------------------------------------------


@dataclass
class Usuario:
    id_usuario: str
    nome: str
    email: str
    senha: str
    tipo: str          # "ALUNO", "PROFESSOR", "DIRETOR"
    chave_pub: str
    chave_pri: str


def carregar_usuarios() -> List[Usuario]:
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        users: List[Usuario] = []
        for d in data:
            users.append(
                Usuario(
                    id_usuario=d.get("id_usuario", str(uuid.uuid4())),
                    nome=d["nome"],
                    email=d["email"],
                    senha=d["senha"],
                    tipo=d["tipo"],
                    chave_pub=d["chave_pub"],
                    chave_pri=d["chave_pri"],
                )
            )
        return users
    except Exception:
        return []


def salvar_usuarios(usuarios: List[Usuario]) -> None:
    data = [asdict(u) for u in usuarios]
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------
# Funções auxiliares
# --------------------------------------------------------------------


def normalizar_frase(frase: str, prefixo: str) -> str:
    """
    Normaliza a frase (sequência de palavras) e adiciona prefixo.
    Ex.: "meu segredo 123" -> "PRI-meu segredo 123"
    """
    core = " ".join(frase.strip().split())
    return f"{prefixo}-{core}"


def start_backend():
    """Sobe o servidor HTTP do nó em background."""
    ring.run_server(host="", port=ring.PORT)


# --------------------------------------------------------------------
# GUI do nó
# --------------------------------------------------------------------


class NodeGUI:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title(f"Nó EDUCOIN - Porta {ring.PORT}")
        self.master.geometry("950x600")

        self.usuarios: List[Usuario] = carregar_usuarios()
        self.usuario_logado: Optional[Usuario] = None

        # ----------------- topo: nó e anel -----------------

        frame_top = ttk.Frame(master, padding=5)
        frame_top.pack(fill=tk.X)

        ttk.Label(
            frame_top,
            text=f"Nó local: ID={ring.NODE_ID}  Porta={ring.PORT}"
        ).grid(row=0, column=0, columnspan=4, sticky="w")

        ttk.Label(frame_top, text="Próximo nó (http://ip:porta):").grid(
            row=1, column=0, sticky="w", pady=(5, 0)
        )

        self.entry_next = ttk.Entry(frame_top, width=40)
        self.entry_next.grid(row=1, column=1, sticky="we", padx=5, pady=(5, 0))
        self.entry_next.insert(0, ring.noh_conectado)

        ttk.Button(
            frame_top,
            text="Atualizar",
            command=self.atualizar_noh_conectado
        ).grid(row=1, column=2, sticky="e", pady=(5, 0))

        ttk.Button(
            frame_top,
            text="Login / Cadastro",
            command=self.abrir_login_dialog
        ).grid(row=1, column=3, sticky="e", padx=5)

        frame_top.columnconfigure(1, weight=1)

        # ----------------- info usuário -----------------

        frame_user = ttk.Frame(master, padding=5)
        frame_user.pack(fill=tk.X)

        self.label_usuario = ttk.Label(frame_user, text="Usuário: (não logado)")
        self.label_usuario.grid(row=0, column=0, sticky="w")

        self.label_chave = ttk.Label(frame_user, text="Minha chave pública: -")
        self.label_chave.grid(row=1, column=0, sticky="w")

        frame_user.columnconfigure(0, weight=1)

        # ----------------- botões: eleição + mural -----------------

        frame_btns = ttk.Frame(master, padding=5)
        frame_btns.pack(fill=tk.X)

        ttk.Button(
            frame_btns,
            text="Iniciar eleição",
            command=self.iniciar_eleicao
        ).grid(row=0, column=0, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Ver leader",
            command=self.ver_leader
        ).grid(row=0, column=1, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Ver mural",
            command=self.ver_mural
        ).grid(row=0, column=2, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Postar no mural",
            command=self.postar_mural_dialog
        ).grid(row=0, column=3, padx=5, pady=2)

        # ----------------- abas principais -----------------

        notebook = ttk.Notebook(master)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_edu = ttk.Frame(notebook, padding=5)
        notebook.add(self.tab_edu, text="EduCoin")

        self.tab_block = ttk.Frame(notebook, padding=5)
        notebook.add(self.tab_block, text="Blockchain")

        self._montar_tab_edu()
        self._montar_tab_block()

        # ----------------- log -----------------

        frame_log = ttk.Frame(master, padding=5)
        frame_log.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            frame_log, wrap=tk.WORD, height=8
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self._log("GUI iniciada. Servidor rodando em background.")
        self._log(f"Nó local: {ring.NODE_ID}, porta {ring.PORT}")

        # abre login/cadastro ao iniciar
        self.master.after(300, self.abrir_login_dialog)

    # ----------------------------------------------------------------
    # construção das abas
    # ----------------------------------------------------------------

    def _montar_tab_edu(self):
        # Saldo
        ttk.Label(self.tab_edu, text="Chave pública para consultar saldo:").grid(
            row=0, column=0, sticky="w"
        )
        self.entry_chave_saldo = ttk.Entry(self.tab_edu, width=60)
        self.entry_chave_saldo.grid(row=1, column=0, sticky="we", pady=2, columnspan=2)

        ttk.Button(
            self.tab_edu,
            text="Consultar saldo",
            command=self.consultar_saldo
        ).grid(row=1, column=2, padx=5)

        self.label_saldo = ttk.Label(self.tab_edu, text="Saldo: -")
        self.label_saldo.grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 5))

        ttk.Separator(self.tab_edu, orient="horizontal").grid(
            row=3, column=0, columnspan=3, sticky="we", pady=5
        )

        # Transferência
        ttk.Label(
            self.tab_edu,
            text="Transferência (da sua carteira para outra chave pública):"
        ).grid(row=4, column=0, columnspan=3, sticky="w")

        ttk.Label(self.tab_edu, text="Chave pública de destino:").grid(
            row=5, column=0, sticky="w", pady=(5, 0)
        )
        self.entry_transfer_dest = ttk.Entry(self.tab_edu, width=50)
        self.entry_transfer_dest.grid(row=6, column=0, columnspan=2, sticky="we")

        ttk.Label(self.tab_edu, text="Valor (EDU):").grid(
            row=5, column=2, sticky="w", pady=(5, 0)
        )
        self.entry_transfer_valor = ttk.Entry(self.tab_edu, width=10)
        self.entry_transfer_valor.grid(row=6, column=2, sticky="w")

        ttk.Button(
            self.tab_edu,
            text="Transferir",
            command=self.transferir_moedas
        ).grid(row=7, column=0, sticky="w", pady=5)

        ttk.Button(
            self.tab_edu,
            text="Ver histórico da minha chave",
            command=self.ver_historico_minha_chave
        ).grid(row=7, column=1, sticky="w", pady=5)

        self.tab_edu.columnconfigure(0, weight=1)
        self.tab_edu.columnconfigure(1, weight=1)

    def _montar_tab_block(self):
        ttk.Button(
            self.tab_block,
            text="Atualizar tamanho da blockchain",
            command=self.ver_blockchain
        ).grid(row=0, column=0, sticky="w", pady=2)

        self.label_blockchain = ttk.Label(self.tab_block, text="Blocos: -")
        self.label_blockchain.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Button(
            self.tab_block,
            text="Ver blockchain (JSON)",
            command=self.mostrar_blockchain_json
        ).grid(row=1, column=0, sticky="w", pady=2)

        self.text_blockchain = scrolledtext.ScrolledText(
            self.tab_block, wrap=tk.WORD, height=15
        )
        self.text_blockchain.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=5)

        self.tab_block.rowconfigure(2, weight=1)
        self.tab_block.columnconfigure(0, weight=1)

    # ----------------------------------------------------------------
    # utilidades
    # ----------------------------------------------------------------

    def _log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _requer_login(self) -> bool:
        if self.usuario_logado is None:
            messagebox.showwarning("Atenção", "Faça login ou cadastre-se primeiro.")
            return False
        return True

    # ----------------------------------------------------------------
    # login / cadastro
    # ----------------------------------------------------------------

    def abrir_login_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Login / Cadastro")
        win.grab_set()

        notebook = ttk.Notebook(win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- aba login ---
        frame_login = ttk.Frame(notebook, padding=5)
        notebook.add(frame_login, text="Login")

        ttk.Label(frame_login, text="Email:").grid(row=0, column=0, sticky="w")
        entry_email_login = ttk.Entry(frame_login, width=35)
        entry_email_login.grid(row=0, column=1, pady=2)

        ttk.Label(frame_login, text="Senha:").grid(row=1, column=0, sticky="w")
        entry_senha_login = ttk.Entry(frame_login, width=35, show="*")
        entry_senha_login.grid(row=1, column=1, pady=2)

        def fazer_login():
            email = entry_email_login.get().strip().lower()
            senha = entry_senha_login.get()
            user = next(
                (u for u in self.usuarios if u.email.lower() == email and u.senha == senha),
                None,
            )
            if not user:
                messagebox.showerror("Erro", "Email ou senha inválidos.")
                return
            self._definir_usuario_logado(user)
            self._log(f"Login realizado: {user.nome} ({user.tipo})")
            win.destroy()

        ttk.Button(frame_login, text="Entrar", command=fazer_login).grid(
            row=2, column=0, columnspan=2, pady=5
        )

        # --- aba cadastro ---
        frame_cad = ttk.Frame(notebook, padding=5)
        notebook.add(frame_cad, text="Cadastrar")

        ttk.Label(frame_cad, text="Nome:").grid(row=0, column=0, sticky="w")
        entry_nome = ttk.Entry(frame_cad, width=35)
        entry_nome.grid(row=0, column=1, pady=2)

        ttk.Label(frame_cad, text="Email:").grid(row=1, column=0, sticky="w")
        entry_email = ttk.Entry(frame_cad, width=35)
        entry_email.grid(row=1, column=1, pady=2)

        ttk.Label(frame_cad, text="Senha:").grid(row=2, column=0, sticky="w")
        entry_senha = ttk.Entry(frame_cad, width=35, show="*")
        entry_senha.grid(row=2, column=1, pady=2)

        ttk.Label(frame_cad, text="Tipo de usuário:").grid(row=3, column=0, sticky="w")
        combo_tipo = ttk.Combobox(
            frame_cad,
            values=["ALUNO", "PROFESSOR", "DIRETOR"],
            state="readonly",
            width=15,
        )
        combo_tipo.grid(row=3, column=1, sticky="w", pady=2)
        combo_tipo.set("ALUNO")

        ttk.Label(
            frame_cad,
            text="Frase para chave PÚBLICA (sequência de palavras):"
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(5, 0))
        entry_frase_pub = ttk.Entry(frame_cad, width=50)
        entry_frase_pub.grid(row=5, column=0, columnspan=2, pady=2)

        ttk.Label(
            frame_cad,
            text="Frase para chave PRIVADA (sequência de palavras):"
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(5, 0))
        entry_frase_pri = ttk.Entry(frame_cad, width=50, show="*")
        entry_frase_pri.grid(row=7, column=0, columnspan=2, pady=2)

        def cadastrar():
            nome = entry_nome.get().strip()
            email = entry_email.get().strip().lower()
            senha = entry_senha.get()
            tipo = combo_tipo.get()
            frase_pub = entry_frase_pub.get().strip()
            frase_pri = entry_frase_pri.get().strip()

            if not (nome and email and senha and frase_pub and frase_pri):
                messagebox.showwarning("Atenção", "Preencha todos os campos.")
                return

            if any(u.email.lower() == email for u in self.usuarios):
                messagebox.showerror("Erro", "Já existe usuário com esse email.")
                return

            chave_pub = normalizar_frase(frase_pub, "PUB")
            chave_pri = normalizar_frase(frase_pri, "PRI")

            if tipo == "ALUNO":
                qtd_inicial = 10
            elif tipo == "PROFESSOR":
                qtd_inicial = 100
            else:  # DIRETOR
                qtd_inicial = 1000

            user = Usuario(
                id_usuario=str(uuid.uuid4()),
                nome=nome,
                email=email,
                senha=senha,
                tipo=tipo,
                chave_pub=chave_pub,
                chave_pri=chave_pri,
            )
            self.usuarios.append(user)
            salvar_usuarios(self.usuarios)

            # Créditos iniciais: BANCO -> usuário
            try:
                resp = requests.post(
                    f"{API_BASE}/transferir",
                    json={
                        "de_chave_pub": "EDUCOIN-BANCO",
                        "para_chave_pub": user.chave_pub,
                        "valor": float(qtd_inicial),
                    },
                    timeout=5,
                )
                if resp.status_code != 200:
                    self._log(f"Falha ao gerar moedas iniciais: {resp.text}")
                else:
                    self._log(
                        f"Moedas iniciais geradas para {user.nome}: {qtd_inicial} EDU"
                    )
            except Exception as e:
                self._log(f"Erro ao contactar backend para moedas iniciais: {e}")

            self._definir_usuario_logado(user)
            messagebox.showinfo("Sucesso", "Cadastro realizado e login efetuado.")
            win.destroy()

        ttk.Button(frame_cad, text="Cadastrar", command=cadastrar).grid(
            row=8, column=0, columnspan=2, pady=8
        )

    def _definir_usuario_logado(self, user: Usuario):
        self.usuario_logado = user
        self.label_usuario.config(text=f"Usuário: {user.nome} ({user.tipo})")
        self.label_chave.config(text=f"Minha chave pública: {user.chave_pub}")
        self.entry_chave_saldo.delete(0, tk.END)
        self.entry_chave_saldo.insert(0, user.chave_pub)

    # ----------------------------------------------------------------
    # anel / mural
    # ----------------------------------------------------------------

    def atualizar_noh_conectado(self):
        novo = self.entry_next.get().strip()
        if not novo:
            messagebox.showwarning("Atenção", "Informe http://ip:porta.")
            return
        ring.noh_conectado = novo
        self._log(f"Próximo nó atualizado para: {novo}")

    def iniciar_eleicao(self):
        try:
            resp = requests.get(f"{API_BASE}/iniciaeleicao", timeout=3)
            self._log(f"/iniciaeleicao: {resp.status_code} {resp.text}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao iniciar eleição: {e}")

    def ver_leader(self):
        try:
            resp = requests.get(f"{API_BASE}/leader", timeout=3)
            data = resp.json()
            self._log(f"Líder atual: {data.get('leader')}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar leader: {e}")

    def ver_mural(self):
        try:
            resp = requests.get(f"{API_BASE}/mural", timeout=3)
            msgs = resp.json()
            self._log("===== MURAL =====")
            if not msgs:
                self._log("(vazio)")
                return
            for msg in msgs:
                linha = f"[{msg.get('id')}] {msg.get('autor')}: {msg.get('texto')}"
                self._log(linha)
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar mural: {e}")

    def postar_mural_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Postar no mural")

        ttk.Label(win, text="Texto da mensagem:").pack(anchor="w", padx=5, pady=(5, 0))
        txt = tk.Text(win, height=4, width=50)
        txt.pack(padx=5, pady=5)

        def enviar():
            conteudo = txt.get("1.0", tk.END).strip()
            if not conteudo:
                messagebox.showwarning("Atenção", "Mensagem vazia.")
                return
            autor = self.usuario_logado.nome if self.usuario_logado else f"NO-{ring.NODE_ID}"
            try:
                resp = requests.post(
                    f"{API_BASE}/mural",
                    json={"texto": conteudo, "autor": autor},
                    timeout=3,
                )
                data = resp.json()
                self._log(f"Mensagem postada: {data}")
                win.destroy()
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao postar no mural: {e}")

        ttk.Button(win, text="Enviar", command=enviar).pack(pady=(0, 5))

    # ----------------------------------------------------------------
    # EduCoin / Blockchain
    # ----------------------------------------------------------------

    def consultar_saldo(self):
        chave = self.entry_chave_saldo.get().strip()
        if not chave:
            messagebox.showwarning("Atenção", "Informe uma chave pública.")
            return
        try:
            resp = requests.get(
                f"{API_BASE}/saldo",
                params={"chave_pub": chave},
                timeout=3,
            )
            data = resp.json()
            saldo = data.get("saldo", 0)
            self.label_saldo.config(text=f"Saldo: {saldo} EDU")
            self._log(f"Saldo de {chave}: {saldo} EDU")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar saldo: {e}")

    def transferir_moedas(self):
        if not self._requer_login():
            return

        destino = self.entry_transfer_dest.get().strip()
        valor_str = self.entry_transfer_valor.get().strip()

        if not destino:
            messagebox.showwarning("Atenção", "Informe a chave de destino.")
            return
        if not valor_str:
            messagebox.showwarning("Atenção", "Informe o valor.")
            return

        try:
            valor = float(valor_str)
        except ValueError:
            messagebox.showwarning("Atenção", "Valor inválido.")
            return

        if valor <= 0:
            messagebox.showwarning("Atenção", "Valor deve ser positivo.")
            return

        # Confirmação com chave privada (frase)
        frase = simpledialog.askstring(
            "Confirmação",
            "Digite sua chave PRIVADA (frase):",
            show="*",
            parent=self.master,
        )
        if frase is None:
            return

        frase_norm = normalizar_frase(frase, "PRI")
        if frase_norm != self.usuario_logado.chave_pri:
            messagebox.showerror("Erro", "Chave privada incorreta.")
            return

        try:
            resp = requests.post(
                f"{API_BASE}/transferir",
                json={
                    "de_chave_pub": self.usuario_logado.chave_pub,
                    "para_chave_pub": destino,
                    "valor": valor,
                    "frase_privada": frase,
                },
                timeout=5,
            )
            data = resp.json()
            if resp.status_code != 200:
                messagebox.showerror("Erro", f"Falha na transferência: {data}")
                return
            self._log(
                f"Transferência criada: {valor} EDU para {destino} (tx={data.get('tx_id')})"
            )
            messagebox.showinfo("OK", "Transferência registrada na blockchain.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao contactar backend: {e}")

    def ver_historico_minha_chave(self):
        if not self._requer_login():
            return
        chave = self.usuario_logado.chave_pub
        try:
            resp = requests.get(
                f"{API_BASE}/historico",
                params={"chave_pub": chave},
                timeout=5,
            )
            lista = resp.json()
            self._log(f"===== HISTÓRICO da chave {chave} =====")
            if not lista:
                self._log("(nenhuma transação)")
                return
            for tx in lista:
                self._log(
                    f"{tx.get('timestamp')}: "
                    f"{tx.get('de_chave_pub')} -> {tx.get('para_chave_pub')} "
                    f"| {tx.get('valor')} EDU"
                )
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar histórico: {e}")

    def ver_blockchain(self):
        try:
            resp = requests.get(f"{API_BASE}/blockchain", timeout=5)
            chain = resp.json()
            tam = len(chain) if isinstance(chain, list) else "?"
            self.label_blockchain.config(text=f"Blocos: {tam}")
            self._log(f"Blockchain possui {tam} blocos.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar blockchain: {e}")

    def mostrar_blockchain_json(self):
        try:
            resp = requests.get(f"{API_BASE}/blockchain", timeout=5)
            chain = resp.json()
            self.text_blockchain.delete("1.0", tk.END)
            self.text_blockchain.insert(
                tk.END, json.dumps(chain, ensure_ascii=False, indent=2)
            )
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar blockchain: {e}")


# --------------------------------------------------------------------
# main
# --------------------------------------------------------------------


if __name__ == "__main__":
    # sobe o backend HTTP em background
    backend_thread = threading.Thread(
        target=start_backend,
        daemon=True,
    )
    backend_thread.start()

    # inicia a interface gráfica
    root = tk.Tk()
    app = NodeGUI(root)
    root.mainloop()
