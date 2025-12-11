import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import requests
import Funcões as ring  # importa o módulo do nó (Funcões.py)

# Base das chamadas HTTP (ele usa a mesma PORT definida em Funcões.py)
API_BASE = f"http://127.0.0.1:{ring.PORT}"


def start_backend():
    """
    Sobe o servidor HTTP do nó em uma thread separada.
    IMPORTANTE: não execute Funcões.py direto em outro terminal ao mesmo tempo,
    senão a porta fica ocupada.
    """
    ring.run_server(host="", port=ring.PORT)


class NodeGUI:
    def __init__(self, master):
        self.master = master
        self.master.title(f"Controle do Nó {ring.NODE_ID}")
        self.master.geometry("900x550")

        # ----- FRAME 1: Info do nó / próximo nó -----
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

        btn_atualizar = ttk.Button(
            frame_top,
            text="Atualizar",
            command=self.atualizar_noh_conectado
        )
        btn_atualizar.grid(row=1, column=2, sticky="e", pady=(5, 0))

        frame_top.columnconfigure(1, weight=1)

        # ----- FRAME 2: Botões de anel/mural -----
        frame_btns = ttk.Frame(master, padding=5)
        frame_btns.pack(fill=tk.X)

        ttk.Button(
            frame_btns,
            text="Iniciar Eleição",
            command=self.iniciar_eleicao
        ).grid(row=0, column=0, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Ver Leader (/leader)",
            command=self.ver_leader
        ).grid(row=0, column=1, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Sincronizar agora (/sync_request)",
            command=self.sincronizar_agora
        ).grid(row=0, column=2, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Ver Mural (/mural)",
            command=self.ver_mural
        ).grid(row=1, column=0, padx=5, pady=2)

        ttk.Button(
            frame_btns,
            text="Postar no Mural",
            command=self.postar_mural_dialog
        ).grid(row=1, column=1, padx=5, pady=2)

        # ----- FRAME 3: Info VC + usuário + chave local -----
        frame_info = ttk.Frame(master, padding=5)
        frame_info.pack(fill=tk.X)

        self.label_vc = ttk.Label(frame_info, text="Relógio (VC): {}")
        self.label_vc.grid(row=0, column=0, sticky="w")

        btn_login = ttk.Button(
            frame_info,
            text="Login / editar usuário",
            command=self.abrir_login_dialog
        )
        btn_login.grid(row=0, column=1, sticky="e", padx=5)

        self.label_usuario = ttk.Label(
            frame_info,
            text=f"Usuário: {ring.usuario_local.nome}"
        )
        self.label_usuario.grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        self.label_chave = ttk.Label(
            frame_info,
            text=f"Minha chave pública: {ring.usuario_local.chave_pub}"
        )
        self.label_chave.grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 0))

        frame_info.columnconfigure(0, weight=1)

        # ----- FRAME 4: Abas (EduCoin / Marketplace) -----
        notebook = ttk.Notebook(master)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_edu = ttk.Frame(notebook, padding=5)
        notebook.add(self.tab_edu, text="EduCoin / Blockchain")

        self.tab_market = ttk.Frame(notebook, padding=5)
        notebook.add(self.tab_market, text="Marketplace")

        self._montar_tab_edu()
        self._montar_tab_market()

        # ----- FRAME 5: Log principal -----
        frame_log = ttk.Frame(master, padding=5)
        frame_log.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            frame_log, wrap=tk.WORD, height=8
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self._log("GUI iniciada. Servidor rodando em background.")
        self._log(f"Nó local: {ring.NODE_ID}, porta {ring.PORT}")
        self._log(f"Usuário local: {ring.usuario_local.nome}")
        self._log(f"Chave pública local: {ring.usuario_local.chave_pub}")

        # Atualiza label do VC periodicamente
        self._atualizar_label_vc()

    # ============================
    #    Construção das abas
    # ============================

    def _montar_tab_edu(self):
        # Saldo
        ttk.Label(self.tab_edu, text="Chave pública para consultar saldo:").grid(
            row=0, column=0, sticky="w"
        )
        self.entry_chave_saldo = ttk.Entry(self.tab_edu, width=50)
        self.entry_chave_saldo.grid(row=1, column=0, sticky="we", pady=2)
        self.entry_chave_saldo.insert(0, ring.usuario_local.chave_pub)

        ttk.Button(
            self.tab_edu,
            text="Consultar saldo (/saldo)",
            command=self.consultar_saldo
        ).grid(row=1, column=1, padx=5)

        self.label_saldo = ttk.Label(self.tab_edu, text="Saldo: -")
        self.label_saldo.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 5))

        # Blockchain
        ttk.Button(
            self.tab_edu,
            text="Ver tamanho da blockchain (/blockchain)",
            command=self.ver_blockchain
        ).grid(row=3, column=0, sticky="w", pady=2)

        self.label_blockchain = ttk.Label(self.tab_edu, text="Blocos: -")
        self.label_blockchain.grid(row=3, column=1, sticky="w")

        # Separador
        ttk.Separator(self.tab_edu, orient="horizontal").grid(
            row=4, column=0, columnspan=2, sticky="we", pady=5
        )

        # Recompensas
        ttk.Label(
            self.tab_edu,
            text="Recompensas (executadas no nó local, não via HTTP):"
        ).grid(row=5, column=0, columnspan=2, sticky="w")

        ttk.Button(
            self.tab_edu,
            text="Recompensa Monitoria",
            command=self.recompensa_monitoria_dialog
        ).grid(row=6, column=0, sticky="w", pady=2)

        ttk.Button(
            self.tab_edu,
            text="Recompensa Nota",
            command=self.recompensa_nota_dialog
        ).grid(row=6, column=1, sticky="w", pady=2)

        # Separador para transferência
        ttk.Separator(self.tab_edu, orient="horizontal").grid(
            row=7, column=0, columnspan=2, sticky="we", pady=5
        )

        # Transferência entre usuários
        ttk.Label(
            self.tab_edu,
            text="Transferência entre usuários (minha carteira → outra chave):"
        ).grid(row=8, column=0, columnspan=2, sticky="w")

        ttk.Label(self.tab_edu, text="Chave pública de destino:").grid(
            row=9, column=0, sticky="w"
        )
        self.entry_transfer_dest = ttk.Entry(self.tab_edu, width=50)
        self.entry_transfer_dest.grid(row=10, column=0, sticky="we", pady=2)

        ttk.Label(self.tab_edu, text="Valor (EDU):").grid(
            row=9, column=1, sticky="w"
        )
        self.entry_transfer_valor = ttk.Entry(self.tab_edu, width=15)
        self.entry_transfer_valor.grid(row=10, column=1, sticky="w", pady=2)

        ttk.Button(
            self.tab_edu,
            text="Transferir moedas",
            command=self.transferir_moedas
        ).grid(row=11, column=0, sticky="w", pady=(2, 5))

        ttk.Button(
            self.tab_edu,
            text="Ver histórico da chave",
            command=self.ver_historico_chave
        ).grid(row=11, column=1, sticky="w", pady=(2, 5))

        self.tab_edu.columnconfigure(0, weight=1)

    def _montar_tab_market(self):
        ttk.Label(
            self.tab_market,
            text="Benefícios disponíveis (Marketplace interno):"
        ).grid(row=0, column=0, sticky="w")

        ttk.Button(
            self.tab_market,
            text="Listar benefícios",
            command=self.listar_beneficios
        ).grid(row=1, column=0, sticky="w", pady=2)

        self.text_beneficios = tk.Text(self.tab_market, height=6)
        self.text_beneficios.grid(row=2, column=0, columnspan=2, sticky="nsew")

        ttk.Label(
            self.tab_market,
            text="Resgatar benefício para chave pública:"
        ).grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.entry_chave_market = ttk.Entry(self.tab_market, width=50)
        self.entry_chave_market.grid(row=4, column=0, sticky="we")
        self.entry_chave_market.insert(0, ring.usuario_local.chave_pub)

        ttk.Label(
            self.tab_market,
            text="ID do benefício (ex: lab_extra, mentoria):"
        ).grid(row=5, column=0, sticky="w", pady=(5, 0))

        self.entry_beneficio_id = ttk.Entry(self.tab_market, width=20)
        self.entry_beneficio_id.grid(row=6, column=0, sticky="w")

        ttk.Button(
            self.tab_market,
            text="Resgatar",
            command=self.resgatar_beneficio
        ).grid(row=6, column=1, sticky="w", padx=5)

        ttk.Button(
            self.tab_market,
            text="Listar resgates",
            command=self.listar_resgates
        ).grid(row=7, column=0, sticky="w", pady=(5, 0))

        self.text_resgates = tk.Text(self.tab_market, height=6)
        self.text_resgates.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=(2, 0))

        self.tab_market.rowconfigure(2, weight=1)
        self.tab_market.rowconfigure(8, weight=1)
        self.tab_market.columnconfigure(0, weight=1)

    # ============================
    #   Funções de utilidade
    # ============================

    def _log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _atualizar_label_vc(self):
        try:
            vc_copy = ring.vc_get_copy()
            self.label_vc.config(text=f"Relógio (VC): {vc_copy}")
        except Exception:
            pass
        # agenda próxima atualização
        self.master.after(1000, self._atualizar_label_vc)

    # ============================
    #   Login / usuário
    # ============================

    def abrir_login_dialog(self):
        """
        Login bem simples: apenas edita os dados do usuario_local já criado
        em Funcões.py (nome, email, matrícula). Não muda a chave pública.
        """
        win = tk.Toplevel(self.master)
        win.title("Login / editar usuário")

        ttk.Label(win, text="Nome:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        entry_nome = ttk.Entry(win, width=40)
        entry_nome.grid(row=0, column=1, padx=5, pady=5)
        entry_nome.insert(0, getattr(ring.usuario_local, "nome", ""))

        ttk.Label(win, text="Email:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        entry_email = ttk.Entry(win, width=40)
        entry_email.grid(row=1, column=1, padx=5, pady=5)
        entry_email.insert(0, getattr(ring.usuario_local, "email", ""))

        ttk.Label(win, text="Matrícula:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        entry_mat = ttk.Entry(win, width=20)
        entry_mat.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        entry_mat.insert(0, getattr(ring.usuario_local, "matricula", ""))

        def salvar():
            ring.usuario_local.nome = entry_nome.get().strip() or ring.usuario_local.nome
            ring.usuario_local.email = entry_email.get().strip() or ring.usuario_local.email
            if hasattr(ring.usuario_local, "matricula"):
                ring.usuario_local.matricula = entry_mat.get().strip() or ring.usuario_local.matricula

            self.label_usuario.config(text=f"Usuário: {ring.usuario_local.nome}")
            self.entry_chave_saldo.delete(0, tk.END)
            self.entry_chave_saldo.insert(0, ring.usuario_local.chave_pub)
            self.entry_chave_market.delete(0, tk.END)
            self.entry_chave_market.insert(0, ring.usuario_local.chave_pub)

            self._log(f"Usuário atualizado: {ring.usuario_local.nome} ({ring.usuario_local.email})")
            win.destroy()

        ttk.Button(win, text="Salvar", command=salvar).grid(
            row=3, column=0, columnspan=2, pady=10
        )

    # ============================
    #   Botões do anel/mural
    # ============================

    def atualizar_noh_conectado(self):
        novo = self.entry_next.get().strip()
        if not novo:
            messagebox.showwarning("Atenção", "Informe um endereço http://ip:porta.")
            return
        ring.noh_conectado = novo
        self._log(f"Próximo nó atualizado para: {novo}")

    def iniciar_eleicao(self):
        try:
            resp = requests.get(f"{API_BASE}/iniciaeleicao", timeout=3)
            data = resp.json()
            self._log(f"Eleição iniciada: {data}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao iniciar eleição: {e}")

    def ver_leader(self):
        try:
            resp = requests.get(f"{API_BASE}/leader", timeout=3)
            data = resp.json()
            self._log(f"Líder atual: {data}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar leader: {e}")

    def sincronizar_agora(self):
        try:
            resp = requests.post(f"{API_BASE}/sync_request", json={}, timeout=5)
            self._log(f"Sync_request resposta: {resp.status_code} {resp.text}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao sincronizar: {e}")

    def ver_mural(self):
        try:
            resp = requests.get(f"{API_BASE}/mural", timeout=3)
            msgs = resp.json()
            self._log("===== MURAL =====")
            if not msgs:
                self._log("(vazio)")
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
            try:
                resp = requests.post(
                    f"{API_BASE}/mural",
                    json={
                        "texto": conteudo,
                        "autor": ring.usuario_local.nome or ring.NODE_ID
                    },
                    timeout=3
                )
                data = resp.json()
                self._log(f"Mensagem postada: {data}")
                win.destroy()
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao postar no mural: {e}")

        ttk.Button(win, text="Enviar", command=enviar).pack(pady=(0, 5))

    # ============================
    #   EduCoin / Blockchain
    # ============================

    def consultar_saldo(self):
        chave = self.entry_chave_saldo.get().strip()
        if not chave:
            messagebox.showwarning("Atenção", "Informe uma chave pública.")
            return
        try:
            resp = requests.get(
                f"{API_BASE}/saldo",
                params={"chave_pub": chave},
                timeout=3
            )
            data = resp.json()
            saldo = data.get("saldo", 0)
            self.label_saldo.config(text=f"Saldo: {saldo} EDU")
            self._log(f"Saldo de {chave}: {saldo} EDU")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar saldo: {e}")

    def ver_blockchain(self):
        try:
            resp = requests.get(f"{API_BASE}/blockchain", timeout=3)
            chain = resp.json()
            tam = len(chain) if isinstance(chain, list) else "?"
            self.label_blockchain.config(text=f"Blocos: {tam}")
            self._log(f"Blockchain possui {tam} blocos.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao consultar blockchain: {e}")

    def recompensa_monitoria_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Recompensa Monitoria")

        ttk.Label(win, text="Duração (horas):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        entry_horas = ttk.Entry(win, width=10)
        entry_horas.grid(row=0, column=1, padx=5, pady=5)
        entry_horas.insert(0, "1")

        ttk.Label(win, text="Feedback (0-10, opcional):").grid(row=1, column=0, sticky="w", padx=5)
        entry_fb = ttk.Entry(win, width=10)
        entry_fb.grid(row=1, column=1, padx=5, pady=5)

        def gerar():
            try:
                horas = float(entry_horas.get())
                fb = entry_fb.get().strip()
                fb_val = float(fb) if fb else None
                tx = ring.registrar_monitoria(
                    ring.usuario_local,
                    aluno_atendido=None,
                    duracao_horas=horas,
                    descricao="monitoria lançada via GUI"
                )
                self._log(
                    f"Tx monitoria criada: id={tx.id_tx}, valor={tx.valor}, "
                    f"para={tx.para_chave_pub}"
                )
                win.destroy()
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao registrar monitoria: {e}")

        ttk.Button(win, text="Gerar recompensa", command=gerar).grid(
            row=2, column=0, columnspan=2, pady=5
        )

    def recompensa_nota_dialog(self):
        win = tk.Toplevel(self.master)
        win.title("Recompensa por Nota")

        ttk.Label(win, text="Nota (0-10):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        entry_nota = ttk.Entry(win, width=10)
        entry_nota.grid(row=0, column=1, padx=5, pady=5)
        entry_nota.insert(0, "8")

        def gerar():
            try:
                nota = float(entry_nota.get())
                tx = ring.registrar_nota(
                    ring.usuario_local,
                    disciplina="DISCIPLINA-EXEMPLO",
                    nota=nota
                )
                if tx is None:
                    messagebox.showinfo("Info", "Nota não gera recompensa (abaixo do corte).")
                    win.destroy()
                    return
                self._log(
                    f"Tx nota criada: id={tx.id_tx}, valor={tx.valor}, "
                    f"para={tx.para_chave_pub}"
                )
                win.destroy()
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao registrar nota: {e}")

        ttk.Button(win, text="Gerar recompensa", command=gerar).grid(
            row=1, column=0, columnspan=2, pady=5
        )

    def transferir_moedas(self):
        """
        Cria uma transação de transferência:
        de = carteira do usuario_local
        para = chave pública digitada
        valor = valor digitado
        Usa diretamente Transacao + no_blockchain.enviar_transacao.
        """
        destino = self.entry_transfer_dest.get().strip()
        valor_str = self.entry_transfer_valor.get().strip()

        if not destino:
            messagebox.showwarning("Atenção", "Informe a chave pública de destino.")
            return
        if not valor_str:
            messagebox.showwarning("Atenção", "Informe o valor a transferir.")
            return

        try:
            valor = float(valor_str)
        except ValueError:
            messagebox.showwarning("Atenção", "Valor inválido.")
            return
        if valor <= 0:
            messagebox.showwarning("Atenção", "Valor deve ser positivo.")
            return

        try:
            ring.vc_increment()
            tx = ring.Transacao(
                de_chave_pub=ring.usuario_local.chave_pub,
                para_chave_pub=destino,
                valor=valor,
                vc=ring.vc_get_copy(),
            )
            ring.no_blockchain.enviar_transacao(tx)
            self._log(
                f"Transferência criada: {tx.id_tx} | "
                f"{valor} EDU para {destino}"
            )
            messagebox.showinfo("OK", "Transferência registrada (aguarda entrar em bloco).")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao criar transferência: {e}")

    def ver_historico_chave(self):
        """
        Mostra no log o histórico de transações de uma chave pública,
        usando no_blockchain.obter_historico.
        """
        chave = self.entry_chave_saldo.get().strip()
        if not chave:
            messagebox.showwarning("Atenção", "Informe uma chave pública.")
            return
        try:
            historico = ring.no_blockchain.obter_historico(chave)
            self._log(f"===== HISTÓRICO da chave {chave} =====")
            if not historico:
                self._log("(nenhuma transação encontrada)")
                return
            for tx in historico:
                sentido = "→"
                self._log(
                    f"{tx.timestamp}: {tx.de_chave_pub} {sentido} "
                    f"{tx.para_chave_pub} | {tx.valor} EDU | id={tx.id_tx}"
                )
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao obter histórico: {e}")

    # ============================
    #   Marketplace
    # ============================

    def listar_beneficios(self):
        try:
            beneficios = ring.listar_beneficios()
            self.text_beneficios.delete("1.0", tk.END)
            for b in beneficios:
                linha = f"{b['id']}: {b['nome']} (custo: {b['custo']} EDU)\n"
                self.text_beneficios.insert(tk.END, linha)
            self._log("Benefícios listados na aba Marketplace.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao listar benefícios: {e}")

    def resgatar_beneficio(self):
        chave = self.entry_chave_market.get().strip()
        bid = self.entry_beneficio_id.get().strip()
        if not chave or not bid:
            messagebox.showwarning("Atenção", "Informe chave pública e ID do benefício.")
            return
        try:
            registro = ring.resgatar_beneficio(chave, bid)
            self._log(
                f"Benefício resgatado: {registro['beneficio_id']} "
                f"por {chave}, custo={registro['custo']} EDU, tx={registro['tx_id']}"
            )
            messagebox.showinfo("OK", "Benefício resgatado. Veja log.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao resgatar benefício: {e}")

    def listar_resgates(self):
        try:
            chave = self.entry_chave_market.get().strip() or None
            resgates = ring.listar_resgates(chave)
            self.text_resgates.delete("1.0", tk.END)
            for r in resgates:
                linha = (
                    f"{r['chave_pub']} -> {r['beneficio_nome']} "
                    f"(custo={r['custo']} EDU) tx={r['tx_id']}\n"
                )
                self.text_resgates.insert(tk.END, linha)
            self._log("Resgates listados na aba Marketplace.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao listar resgates: {e}")


# ============================
#   MAIN
# ============================

if __name__ == "__main__":
    # Sobe o backend em background
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()

    # Inicia GUI
    root = tk.Tk()
    app = NodeGUI(root)
    root.mainloop()
