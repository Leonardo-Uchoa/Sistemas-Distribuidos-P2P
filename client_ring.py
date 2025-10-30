import http.server
import socketserver
import json
import requests
import threading
import uuid
import logging
from typing import List, Dict, Optional
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import time
import random  # 🔹 Adicionado

# ========== CONFIG ==========
NODE_ID: int = random.randint(1, 10000)  # 🔹 Gerado aleatoriamente
PORT: int = 8001
# URL do próximo nó no anel (ajuste conforme sua topologia)
noh_conectado: str = "http://10.80.40.253:8000"

lider: Optional[int] = None
participante: bool = False
mural: List[Dict] = []  # mural compartilhado (lista de mensagens únicas)
# ============================

lock = threading.Lock()
TIMEOUT_S = 3
REQUEST_RETRIES = 2  # tentativas totais
SYNC_INTERVAL_S = 5  # intervalo em segundos para o líder sincronizar com o próximo nó

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Reutilizar sessão para keep-alive
session = requests.Session()

# ========== Vector Lamport (Vector Clock) ==========
# Usamos um dicionário esparso {node_id: counter}
vector_clock: Dict[int, int] = {}


def vc_increment():
    """Incrementa a entrada do NODE_ID no vector clock (evento local / antes de enviar)."""
    with lock:
        vector_clock[NODE_ID] = vector_clock.get(NODE_ID, 0) + 1
        logging.debug(f"VC incrementado: {vector_clock}")


def vc_merge(received_vc: Optional[Dict]):
    """
    Faz o merge entre o vector clock local e o recebido (element-wise max),
    e depois incrementa o relógio local (regra de recebimento).
    """
    if not received_vc:
        # ainda incrementamos? Não, só incrementamos após um RECEBIMENTO válido.
        return

    with lock:
        # received_vc pode ter chaves string (por JSON); convertemos para int quando possível
        for k_str, v in received_vc.items():
            try:
                k = int(k_str)
            except Exception:
                # se a chave não for convertível, ignora
                continue
            if not isinstance(v, int):
                # tentar converter
                try:
                    v = int(v)
                except Exception:
                    continue
            current = vector_clock.get(k, 0)
            if v > current:
                vector_clock[k] = v
        # depois de mesclar, incrementa a posição local (recebimento)
        vector_clock[NODE_ID] = vector_clock.get(NODE_ID, 0) + 1
        logging.debug(f"VC mesclado e incrementado após recebimento: {vector_clock}")


def vc_get_copy() -> Dict[str, int]:
    """Retorna uma cópia do vector clock com chaves como strings (pronto para JSON)."""
    with lock:
        return {str(k): int(v) for k, v in vector_clock.items()}


# ========== Redes: async_post agora anexa vc automaticamente (se não existir) ==========
def async_post(url: str, payload: dict, max_retries: int = REQUEST_RETRIES):
    """Faz POST assíncrono com retries básicos e checagem de status HTTP.
    Não retorna nada; loga erros.
    """

    # captura snapshot do payload para não modificar o original do chamador
    payload_snapshot = dict(payload) if payload is not None else {}

    # Anexa o VC atual se o payload não tiver 'vc'
    if "vc" not in payload_snapshot:
        payload_snapshot["vc"] = vc_get_copy()

    def _run():
        for attempt in range(1, max_retries + 1):
            try:
                resp = session.post(url, json=payload_snapshot, timeout=TIMEOUT_S)
                # aceitar apenas 2xx como sucesso
                if 200 <= resp.status_code < 300:
                    logging.info(f"POST {url} sucesso (status={resp.status_code})")
                    return
                else:
                    logging.warning(f"POST {url} respondeu {resp.status_code}: {resp.text}")
            except requests.RequestException as e:
                logging.warning(f"Falha POST {url} (tentativa {attempt}): {e}")
        logging.error(f"Desistindo de POST para {url} depois de {max_retries} tentativas")

    threading.Thread(target=_run, daemon=True).start()


def sync_with_next_once(destino: Optional[str] = None) -> int:
    """Tenta buscar /mural do destino e incorporar mensagens novas no mural local.
    Retorna o número de mensagens adicionadas.
    Se destino não for fornecido, usa noh_conectado.
    Além disso, depois de adicionar, replica as mensagens novas para o destino (para propagar unificação).
    """
    added = 0
    if destino is None:
        with lock:
            destino = noh_conectado
    if not destino:
        return 0

    try:
        logging.info(f"Sincronizando mural com {destino}")
        resp = session.get(destino + "/mural", timeout=TIMEOUT_S)
        if resp.status_code != 200:
            logging.warning(f"GET {destino}/mural devolveu status {resp.status_code}")
            return 0
        other_mural = resp.json()
        if not isinstance(other_mural, list):
            logging.warning("Resposta do /mural não é lista")
            return 0

        new_msgs = []
        with lock:
            existing_ids = {m["id"] for m in mural}
            for msg in other_mural:
                mid = str(msg.get("id"))
                if mid not in existing_ids:
                    # preservar possível vc que veio com a mensagem
                    mural.append(
                        {
                            "id": mid,
                            "autor": msg.get("autor"),
                            "texto": msg.get("texto", ""),
                            "vc": msg.get("vc"),
                        }
                    )
                    new_msgs.append({"id": mid, "autor": msg.get("autor"), "texto": msg.get("texto", ""), "vc": msg.get("vc")})
                    added += 1
        if added:
            logging.info(f"Sincronização: adicionadas {added} mensagens do {destino}")
            # replicar mensagens novas para o próximo nó para propagar unificação
            # isso ajuda a que todo anel receba a versão unificada
            for msg in new_msgs:
                async_post(destino + "/mural", msg)
    except requests.RequestException as e:
        logging.warning(f"Falha ao sincronizar com {destino}: {e}")
    except ValueError:
        logging.warning("Resposta JSON inválida ao sincronizar mural")
    return added


class NossoHandler(http.server.BaseHTTPRequestHandler):
    server_version = "NossoAnel/0.5"

    def _send_json(self, code: int, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        # Redireciona logs do BaseHTTPRequestHandler para logging
        logging.info("%s - - %s" % (self.client_address[0], format % args))

    # ---------------- GET ----------------
    def do_GET(self):
        global participante, mural, lider
        if self.path.startswith("/iniciaeleicao"):
            with lock:
                participante = True
                destino = noh_conectado
            # Lamport vector: antes de enviar, incrementa relógio local
            vc_increment()
            async_post(destino + "/eleicao", {"candidato": NODE_ID})
            self._send_json(202, {"mensagem": "Eleição iniciada", "meu_id": NODE_ID})

        elif self.path.startswith("/leader"):
            with lock:
                atual = lider
            self._send_json(200, {"leader": atual})

        elif self.path.startswith("/mural"):
            with lock:
                mural_copy = list(mural)
            self._send_json(200, mural_copy)

        else:
            self.send_response(404)
            self.end_headers()

    # ---------------- POST ----------------
    def do_POST(self):
        global participante, lider, mural
        # Forçar Content-Type JSON quando houver body
        length = int(self.headers.get("Content-Length", 0))
        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(length).decode("utf-8") if length else ""

        if length and "application/json" not in content_type:
            self.send_response(415)
            self.end_headers()
            return

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        # Se veio vc no payload, mescla e aplica regra de recebimento (merge + increment)
        try:
            incoming_vc = data.get("vc")
            if incoming_vc:
                vc_merge(incoming_vc)
        except Exception as e:
            logging.warning(f"Erro ao mesclar VC recebido: {e}")

        # -------- ELEIÇÃO --------
        if self.path.startswith("/eleicao"):
            raw_cid = data.get("candidato")
            try:
                cid = int(raw_cid)
            except (TypeError, ValueError):
                self._send_json(400, {"erro": "campo 'candidato' inválido"})
                return

            # Se o candidato é este nó -> sou líder
            if cid == NODE_ID:
                with lock:
                    lider = NODE_ID
                    participante = False
                    destino = noh_conectado
                # antes de enviar notificação de eleito, incrementa (evento local: enviar)
                vc_increment()
                async_post(destino + "/eleito", {"eleito": NODE_ID})
                self._send_json(200, {"mensagem": "Sou líder", "leader": NODE_ID})
                return

            # Encaminhar maior id
            with lock:
                participante = True
                forward_id = NODE_ID if NODE_ID > cid else cid
                destino = noh_conectado
            # incremento local antes de enviar (regra de enviar)
            vc_increment()
            async_post(destino + "/eleicao", {"candidato": forward_id})
            self._send_json(202, {"mensagem": "Eleição encaminhada", "candidato": forward_id})
            return

        elif self.path.startswith("/eleito"):
            raw_eleito = data.get("eleito")
            try:
                eleito = int(raw_eleito)
            except (TypeError, ValueError):
                self._send_json(400, {"erro": "campo 'eleito' inválido"})
                return

            with lock:
                lider = eleito
                participante = False
                sou_lider = NODE_ID == eleito
                destino = noh_conectado
            if not sou_lider:
                # antes de encaminhar, incrementa VC (evento de enviar)
                vc_increment()
                async_post(destino + "/eleito", {"eleito": eleito})
            self._send_json(200, {"mensagem": "Líder reconhecido", "leader": eleito})
            return

        # -------- MURAL --------
        elif self.path.startswith("/mural"):
            texto = data.get("texto", "")
            msg_id = data.get("id") or str(uuid.uuid4())
            autor = data.get("autor", NODE_ID)
            # evitar textos absurdamente grandes
            if not isinstance(texto, str) or len(texto) > 5000:
                self._send_json(400, {"erro": "texto inválido ou muito grande"})
                return

            msg = {"id": str(msg_id), "autor": autor, "texto": texto, "vc": data.get("vc")}

            with lock:
                # evitar duplicatas pelo id
                if any(m["id"] == msg["id"] for m in mural):
                    logging.info("Mensagem já existe no mural: %s", msg["id"])
                    self._send_json(200, msg)
                    # mesmo que seja duplicata, ainda notificamos o ring para que o líder possa unificar
                    try:
                        destino = noh_conectado
                        # enviar sync_request (async_post já adiciona vc automaticamente se necessário)
                        vc_increment()
                        async_post(destino + "/sync_request", {"origin": NODE_ID})
                    except Exception:
                        pass
                    return
                # adiciona a mensagem (preservando vc se presente)
                mural.append(msg)

            # se este nó é líder, replica para o próximo
            with lock:
                is_lider = (lider == NODE_ID)
                destino = noh_conectado

            if is_lider:
                # replicar assíncrono; incluir id para que receptores detectem duplicata
                # async_post anexa vc automaticamente (não sobrescreve se msg já tem vc)
                vc_increment()
                async_post(destino + "/mural", msg)
            else:
                # notificar o anel para que a solicitação alcance o líder e este faça a unificação
                try:
                    vc_increment()
                    async_post(destino + "/sync_request", {"origin": NODE_ID})
                except Exception:
                    pass

            self._send_json(201, msg)
            return

        # -------- SYNC REQUEST --------
        elif self.path.startswith("/sync_request"):
            # Quando um nó recebe /sync_request: se for líder, faz sincronização; senão, encaminha para o próximo nó.
            with lock:
                is_lider = (lider == NODE_ID)
                destino = noh_conectado
            if is_lider:
                added = sync_with_next_once(destino)
                self._send_json(200, {"mensagens_adicionadas": added})
            else:
                # encaminhar para o próximo nó (assíncrono)
                try:
                    vc_increment()
                    async_post(destino + "/sync_request", {"forwarded_by": NODE_ID})
                    self._send_json(202, {"mensagem": "Encaminhado ao próximo nó"})
                except Exception:
                    self._send_json(500, {"erro": "Falha ao encaminhar sync_request"})
            return

        else:
            self.send_response(404)
            self.end_headers()


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


# ============== Sincronização do líder (loop periódico) ==============
def sync_with_next_loop():
    """Loop em background: se este nó for líder, periodicamente busca o /mural do próximo
    e incorpora mensagens novas no mural local."""
    while True:
        try:
            with lock:
                is_lider = (lider == NODE_ID)
                destino = noh_conectado
            if is_lider and destino:
                sync_with_next_once(destino)
        except Exception as e:
            logging.error(f"Erro no loop de sincronização: {e}")
        time.sleep(SYNC_INTERVAL_S)


# ================= GUI =================
# Janela simples com botões para cada endpoint. Ela age como cliente (não substitui o anel).


class ControlGUI:
    def __init__(self, master, base_url: str):
        self.master = master
        self.base = base_url.rstrip("/")
        master.title(f"Controle do Nó {NODE_ID}")

        frame = tk.Frame(master, padx=8, pady=8)
        frame.pack()

        # campo para configurar o próximo nó (noh_conectado)
        cfg_frame = tk.Frame(frame)
        cfg_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 6))
        tk.Label(cfg_frame, text="Próximo nó (http://ip:porta):").grid(row=0, column=0, sticky="w")
        self.next_entry = tk.Entry(cfg_frame, width=40)
        self.next_entry.insert(0, noh_conectado)
        self.next_entry.grid(row=0, column=1, padx=4)
        self.update_next_btn = tk.Button(cfg_frame, text="Atualizar", command=self.update_next)
        self.update_next_btn.grid(row=0, column=2, padx=4)

        self.leader_btn = tk.Button(frame, text="Iniciar Eleição", command=self.inicia_eleicao)
        self.leader_btn.grid(row=1, column=0, sticky="ew", padx=4, pady=4)

        self.get_leader_btn = tk.Button(frame, text="Ver Leader (GET /leader)", command=self.get_leader)
        self.get_leader_btn.grid(row=1, column=1, sticky="ew", padx=4, pady=4)

        self.sync_now_btn = tk.Button(frame, text="Sincronizar agora (líder)", command=self.sync_now)
        self.sync_now_btn.grid(row=1, column=2, sticky="ew", padx=4, pady=4)

        self.get_mural_btn = tk.Button(frame, text="Ver Mural (GET /mural)", command=self.get_mural)
        self.get_mural_btn.grid(row=2, column=0, sticky="ew", padx=4, pady=4)

        self.post_mural_btn = tk.Button(frame, text="Postar no Mural (POST /mural)", command=self.post_mural)
        self.post_mural_btn.grid(row=2, column=1, sticky="ew", padx=4, pady=4)

        # Label que mostra o vector clock atual
        self.vc_label = tk.Label(frame, text="Relógio (VC): {}", anchor="w", justify="left")
        self.vc_label.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(6, 0))

        self.output = scrolledtext.ScrolledText(master, width=80, height=18, state="disabled")
        self.output.pack(padx=8, pady=8)

        self.client_session = requests.Session()

        # iniciar atualização periódica do label do relógio
        self._update_vc_label_periodic()

    def _log(self, text: str):
        self.output.config(state="normal")
        self.output.insert(tk.END, f"{text}\n")
        self.output.see(tk.END)
        self.output.config(state="disabled")

    def _format_vc_for_ui(self) -> str:
        """Formata uma string compacta do vector clock para a UI."""
        with lock:
            if not vector_clock:
                return "{}"
            # ordena por chave para estabilidade visual
            items = sorted(vector_clock.items(), key=lambda x: x[0])
            return "{" + ", ".join(f"{k}:{v}" for k, v in items) + "}"

    def _update_vc_label_periodic(self):
        """Atualiza o label do relógio no UI a cada 1s."""
        self.vc_label.config(text=f"Relógio (VC): {self._format_vc_for_ui()}")
        # agenda próxima atualização
        self.master.after(1000, self._update_vc_label_periodic)

    def update_next(self):
        global noh_conectado
        new = self.next_entry.get().strip()
        if not new:
            messagebox.showwarning("Valor inválido", "Informe o endereço do próximo nó.")
            return
        # simples validação: deve começar com http:// ou https://
        if not (new.startswith("http://") or new.startswith("https://")):
            messagebox.showwarning("Formato inválido", "O endereço deve começar com http:// ou https://")
            return
        with lock:
            noh_conectado = new
        self._log(f"Próximo nó atualizado para: {noh_conectado}")

    def inicia_eleicao(self):
        url = f"{self.base}/iniciaeleicao"
        try:
            r = self.client_session.get(url, timeout=TIMEOUT_S)
            self._log(f"GET {url} -> {r.status_code} {r.text}")
        except requests.RequestException as e:
            self._log(f"Falha ao iniciar eleição: {e}")

    def get_leader(self):
        url = f"{self.base}/leader"
        try:
            r = self.client_session.get(url, timeout=TIMEOUT_S)
            self._log(f"GET {url} -> {r.status_code} {r.text}")
        except requests.RequestException as e:
            self._log(f"Falha ao obter leader: {e}")

    def sync_now(self):
        # Força uma sincronização imediata do líder com o próximo nó
        with lock:
            destino = noh_conectado
            is_lider = (lider == NODE_ID)
        if not is_lider:
            self._log("Apenas o líder pode forçar sincronização.")
            return
        added = sync_with_next_once(destino)
        self._log(f"Sincronização forçada adicionou {added} mensagens.")

    def get_mural(self):
        url = f"{self.base}/mural"
        try:
            r = self.client_session.get(url, timeout=TIMEOUT_S)
            self._log(f"GET {url} -> {r.status_code} {r.text}")
        except requests.RequestException as e:
            self._log(f"Falha ao obter mural: {e}")

    def post_mural(self):
        texto = simpledialog.askstring("Postar no mural", "Texto:")
        if texto is None:
            return

        # Evento local: incrementa o VC antes de enviar (regra do envio)
        vc_increment()
        payload = {"texto": texto, "autor": NODE_ID, "vc": vc_get_copy()}
        url = f"{self.base}/mural"
        try:
            r = self.client_session.post(url, json=payload, timeout=TIMEOUT_S)
            self._log(f"POST {url} -> {r.status_code} {r.text}")
            # se obtiver 201 ou 200, notifica anel para que líder unifique automaticamente
            if r.status_code in (200, 201):
                with lock:
                    destino = noh_conectado
                try:
                    # async_post anexa vc se necessário, mas já temos vc no payload
                    async_post(destino + "/sync_request", {"origin": NODE_ID})
                except Exception:
                    pass
        except requests.RequestException as e:
            self._log(f"Falha ao postar no mural: {e}")


def run_server_in_thread(host: str = "", port: int = PORT):
    httpd = ThreadingTCPServer((host, port), NossoHandler)

    def _serve():
        logging.info(f"Node {NODE_ID} servindo em {host or '0.0.0.0'}:{port}")
        try:
            httpd.serve_forever()
        except Exception as e:
            logging.error("Servidor finalizado: %s", e)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return httpd


if __name__ == "__main__":
    # Inicia servidor API em background
    httpd = run_server_in_thread("", PORT)

    # Inicia thread de sincronização do líder (periódica)
    sync_thread = threading.Thread(target=sync_with_next_loop, daemon=True)
    sync_thread.start()

    # Abre GUI
    root = tk.Tk()
    base_url = f"http://localhost:{PORT}"
    gui = ControlGUI(root, base_url)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        logging.info("Fechando aplicação...")
        httpd.shutdown()
        httpd.server_close()
