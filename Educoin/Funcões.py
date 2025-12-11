"""
Funcões.py
Servidor HTTP de um nó da rede EDUCOIN em anel.

Responsável por:
- Eleição em anel (/iniciaeleicao, /eleicao, /eleito, /leader)
- Mural distribuído (/mural)
- Blockchain EDUCOIN (/saldo, /blockchain, /historico, /tx, /transferir, /minerar)
- Validação de transferência com chave privada
"""

import json
import logging
import os
import random
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import requests

from Classes import No, Transacao, MoedaConfig, Eleicao

# --------------------------------------------------------------------
# Configuração global do nó
# --------------------------------------------------------------------

NODE_ID: int = random.randint(1000, 9999)
PORT: int = 8001          # pode mudar para rodar vários nós
IP_LOCAL: str = "127.0.0.1"

# Próximo nó no anel (editável pela interface)
noh_conectado: str = f"http://{IP_LOCAL}:{PORT}"

# Arquivo de usuários (compartilhado com a GUI)
USERS_FILE = "usuarios.json"

# Relógio vetorial + mural
vc: Dict[str, int] = {}
mural: List[Dict] = []

participante: bool = False       # se já está participando da eleição
lider: Optional[int] = None      # NODE_ID do líder atual, se existir

# --------------------------------------------------------------------
# Blockchain / Moeda
# --------------------------------------------------------------------

# Moeda EDUCOIN com supply máximo
try:
    moeda_config = MoedaConfig(
        nome="EDUCOIN",
        lista_chaves_pub_autorizadas=None,
        time_limit=None,
        max_supply=100_000,
    )
except TypeError:
    # fallback se a assinatura for diferente
    moeda_config = MoedaConfig("EDUCOIN", None, None, 100_000)

eleicao_logica = Eleicao(ip_inicial=str(NODE_ID))

# Usuário local não é usado diretamente aqui,
# a GUI trabalha com os usuários de usuarios.json
usuario_local = None

no_blockchain = No(
    ip=IP_LOCAL,
    porta=PORT,
    usuario=usuario_local,
    eleicao=eleicao_logica,
    moeda_config=moeda_config,
)

# --------------------------------------------------------------------
# Utilidades: usuários / chave privada
# --------------------------------------------------------------------


def carregar_usuarios() -> List[Dict]:
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def validar_chave_privada(chave_pub: str, frase_privada: str) -> bool:
    """
    Verifica se a frase_privada corresponde à chave privada
    armazenada para o dono da chave pública.
    """
    usuarios = carregar_usuarios()
    frase_norm = "PRI-" + " ".join(frase_privada.strip().split())
    for u in usuarios:
        if u.get("chave_pub") == chave_pub:
            return u.get("chave_pri") == frase_norm
    return False

# --------------------------------------------------------------------
# Relógio vetorial
# --------------------------------------------------------------------


def vc_increment():
    chave = str(NODE_ID)
    vc[chave] = vc.get(chave, 0) + 1


def vc_merge(incoming: Dict[str, int]):
    for k, v in incoming.items():
        vc[k] = max(vc.get(k, 0), v)


def vc_get_copy() -> Dict[str, int]:
    return dict(vc)

# --------------------------------------------------------------------
# Handler HTTP
# --------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "EduCoinRing/0.1"

    def log_message(self, format, *args):
        logging.info("HTTP: " + format % args)

    def _send_json(self, code: int, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----------------- GET -----------------

    def do_GET(self):
        global mural, lider

        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/info":
            self._send_json(200, {
                "node_id": NODE_ID,
                "port": PORT,
                "noh_conectado": noh_conectado,
                "leader": lider,
                "vc": vc_get_copy(),
            })
            return

        if path == "/leader":
            self._send_json(200, {"leader": lider})
            return

        if path == "/mural":
            self._send_json(200, mural)
            return

        if path == "/saldo":
            chave_pub = params.get("chave_pub", [""])[0]
            if not chave_pub:
                self._send_json(400, {"erro": "chave_pub obrigatória"})
                return
            saldo = no_blockchain.calcular_saldo(chave_pub)
            self._send_json(200, {"chave_pub": chave_pub, "saldo": saldo})
            return

        if path == "/blockchain":
            chain = [b.to_dict() for b in no_blockchain.blockchain]
            self._send_json(200, chain)
            return

        if path == "/historico":
            chave_pub = params.get("chave_pub", [""])[0]
            if not chave_pub:
                self._send_json(400, {"erro": "chave_pub obrigatória"})
                return
            historico = no_blockchain.obter_historico(chave_pub)
            self._send_json(200, [tx.to_dict() for tx in historico])
            return

        if path == "/iniciaeleicao":
            self._start_election()
            self._send_json(200, {"status": "ok", "msg": "eleição iniciada"})
            return

        self.send_response(404)
        self.end_headers()

    # ----------------- POST -----------------

    def do_POST(self):
        global mural, participante, lider

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        content_type = self.headers.get("Content-Type", "")

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

        incoming_vc = data.get("vc")
        if isinstance(incoming_vc, dict):
            vc_merge(incoming_vc)

        path = urlparse(self.path).path

        # ---------- mural ----------
        if path == "/mural":
            texto = data.get("texto", "").strip()
            autor = data.get("autor", f"NO-{NODE_ID}")
            if not texto:
                self._send_json(400, {"erro": "texto vazio"})
                return
            vc_increment()
            msg = {
                "id": str(uuid.uuid4()),
                "texto": texto,
                "autor": autor,
                "vc": vc_get_copy(),
                "timestamp": time.time(),
            }
            mural.append(msg)
            self._send_json(200, msg)
            return

        if path == "/sync_request":
            # aqui poderia entrar lógica de sincronização real do mural
            self._send_json(200, {"status": "ok", "adicionados": 0})
            return

        # ---------- eleição em anel ----------
        if path == "/eleicao":
            self._processar_msg_eleicao(data)
            self._send_json(200, {"status": "ok"})
            return

        if path == "/eleito":
            novo_lider = data.get("lider")
            lider = novo_lider
            participante = False
            self._send_json(200, {"status": "ok", "leader": lider})
            return

        # ---------- tx genérica recebida da rede ----------
        if path == "/tx":
            try:
                no_blockchain.receber_transacao(data)
                self._send_json(200, {"status": "ok"})
            except Exception as e:
                logging.exception("Erro ao receber /tx")
                self._send_json(400, {"erro": str(e)})
            return

        # ---------- transferir moedas ----------
        if path == "/transferir":
            self._handle_transferir(data)
            return

        # ---------- minerar manualmente ----------
        if path == "/minerar":
            if not no_blockchain.transacoes_pendentes:
                self._send_json(400, {"erro": "não há transações pendentes"})
                return
            bloco = no_blockchain.criar_bloco()
            ok = no_blockchain.adicionar_bloco(bloco)
            if not ok:
                self._send_json(400, {"erro": "falha ao adicionar bloco"})
                return
            self._send_json(200, {"status": "ok", "indice": bloco.indice})
            return

        self.send_response(404)
        self.end_headers()

    # ----------------- eleição: helpers -----------------

    def _start_election(self):
        global participante
        if participante:
            return
        participante = True
        vc_increment()
        msg = {
            "tipo": "ELEICAO",
            "origem": NODE_ID,
            "candidatos": [NODE_ID],
            "vc": vc_get_copy(),
        }
        self._send_to_next("/eleicao", msg)

    def _processar_msg_eleicao(self, msg: Dict):
        global participante, lider

        origem = msg.get("origem")
        candidatos: List[int] = msg.get("candidatos", [])

        if NODE_ID not in candidatos:
            candidatos.append(NODE_ID)

        if origem == NODE_ID:
            novo_lider = max(candidatos)
            lider = novo_lider
            participante = False
            aviso = {
                "tipo": "ELEITO",
                "lider": novo_lider,
                "vc": vc_get_copy(),
            }
            self._send_to_next("/eleito", aviso)
        else:
            encaminhar = {
                "tipo": "ELEICAO",
                "origem": origem,
                "candidatos": candidatos,
                "vc": vc_get_copy(),
            }
            self._send_to_next("/eleicao", encaminhar)

    def _send_to_next(self, path: str, payload: Dict):
        if not noh_conectado:
            logging.warning("noh_conectado vazio; mensagem não enviada")
            return
        url = f"{noh_conectado}{path}"
        try:
            requests.post(url, json=payload, timeout=3)
        except requests.RequestException as e:
            logging.warning(f"Falha ao enviar para próximo nó {url}: {e}")

    # ----------------- transferência de moedas -----------------

    def _handle_transferir(self, data: Dict):
        try:
            de = data["de_chave_pub"]
            para = data["para_chave_pub"]
            valor = float(data["valor"])
        except Exception:
            self._send_json(400, {"erro": "JSON deve conter de_chave_pub, para_chave_pub, valor"})
            return

        if valor <= 0:
            self._send_json(400, {"erro": "valor deve ser positivo"})
            return

        frase_privada = data.get("frase_privada")

        # Só exige chave privada se não for o BANCO
        if de != "EDUCOIN-BANCO":
            if not frase_privada:
                self._send_json(400, {"erro": "frase_privada obrigatória"})
                return
            if not validar_chave_privada(de, frase_privada):
                self._send_json(403, {"erro": "chave privada incorreta"})
                return

        try:
            # Controle de emissão pelo BANCO
            if de == "EDUCOIN-BANCO" and moeda_config is not None:
                if not moeda_config.pode_emitir(valor):
                    self._send_json(400, {"erro": "max_supply excedido"})
                    return
                moeda_config.registrar_emissao(valor)

            vc_increment()
            tx = Transacao(
                de_chave_pub=de,
                para_chave_pub=para,
                valor=valor,
                vc=vc_get_copy(),
            )

            # Assinatura didática (se método existir)
            if de != "EDUCOIN-BANCO" and frase_privada and hasattr(tx, "assinar"):
                tx.assinar(frase_privada)

            no_blockchain.registrar_transacao_pendente(tx)
            bloco = no_blockchain.criar_bloco()
            ok = no_blockchain.adicionar_bloco(bloco)
            if not ok:
                self._send_json(400, {"erro": "falha ao adicionar bloco"})
                return

            self._send_json(200, {
                "status": "ok",
                "tx_id": tx.id_tx,
                "bloco_indice": bloco.indice,
            })
        except Exception as e:
            logging.exception("Erro em /transferir")
            self._send_json(400, {"erro": str(e)})

# --------------------------------------------------------------------
# Servidor
# --------------------------------------------------------------------


def run_server(host: str = "", port: int = PORT):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    with ThreadingTCPServer((host, port), Handler) as httpd:
        logging.info(f"Servidor iniciado em {host or '0.0.0.0'}:{port} (NODE_ID={NODE_ID})")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Encerrando servidor...")
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    run_server()
