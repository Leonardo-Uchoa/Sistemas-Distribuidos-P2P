"""
Funcões.py
Servidor HTTP de um nó da rede EDUCOIN em anel.

Responsável por:
- Eleição em anel (/eleicao, /eleito, /leader)
- Mural distribuído (/mural) com JSON do líder e participantes
- Blockchain EDUCOIN (/saldo, /blockchain, /historico, /tx, /transferir, /minerar)
- Validação de transferência com chave privada do usuário LOGADO
"""

import json
import logging
import os
import random
import time
import uuid
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import requests

from Classes import No, Transacao, MoedaConfig, Eleicao

# --------------------------------------------------------------------
# Caminho base / arquivo de usuários
# --------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "usuarios.json")

# --------------------------------------------------------------------
# Configuração global do nó
# --------------------------------------------------------------------

IP_LOCAL: str = "127.0.0.1"
PORT: int = 8001  # pode ser alterado para rodar vários nós

# agora o NODE_ID codifica ip:porta (facilita descobrir o líder)
NODE_ID: str = f"{IP_LOCAL}:{PORT}"

# Próximo nó no anel (editável pela interface)
noh_conectado: str = f"http://{IP_LOCAL}:{PORT}"

# Relógio vetorial
vc: Dict[str, int] = {}

# Flag de eleição e líder atual (string "ip:porta")
participante: bool = False
lider: Optional[str] = NODE_ID  # por padrão, este nó começa como líder

# JSON mantido pelo líder e replicado nos demais nós
# participants = lista de dicts: {id_usuario, nome, chave_pub, ip_no, porta_no}
leader_info: Dict = {
    "leader_node_id": NODE_ID,
    "participants": []
}

# chave pública do "banco" institucional
BANCO_CHAVE_PUB = "EDUCOIN-BANCO"

# --------------------------------------------------------------------
# Blockchain / Moeda
# --------------------------------------------------------------------

# Tenta instanciar MoedaConfig com diferentes assinaturas,
# para ser compatível com a versão existente em Classes.py.
moeda_config = None
_last_err = None
for args, kwargs in [
    ([], {"nome": "EDUCOIN",
          "lista_chaves_pub_autorizadas": None,
          "time_limit": None,
          "max_supply": 100_000}),
    (["EDUCOIN", None, None, 100_000], {}),
    (["EDUCOIN", None, None], {}),
    (["EDUCOIN"], {}),
]:
    try:
        moeda_config = MoedaConfig(*args, **kwargs)
        break
    except TypeError as e:
        _last_err = e

if moeda_config is None:
    raise RuntimeError(f"Não foi possível instanciar MoedaConfig: {_last_err}")

eleicao_logica = Eleicao(ip_inicial=str(NODE_ID))

# Usuário local não é usado diretamente aqui; a GUI controla usuários via usuarios.json
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
    """
    Lê o arquivo usuarios.json (se existir) e devolve uma lista de dicts.
    Cada dict deve ter, no mínimo:
    - id_usuario
    - chave_pub
    - chave_pri
    """
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def validar_chave_privada(id_usuario: str, frase_privada: str) -> bool:
    """
    Verifica se a frase_privada corresponde à chave privada
    do USUÁRIO LOGADO (identificado por id_usuario).

    Retorna:
        True  -> frase é exatamente a chave privada salva para esse usuário
        False -> usuário não existe ou frase não confere
    """
    usuarios = carregar_usuarios()

    # normaliza a frase digitada (tira espaços extras e adiciona prefixo PRI-)
    frase_norm = "PRI-" + " ".join(frase_privada.strip().split())

    for u in usuarios:
        if u.get("id_usuario") == id_usuario:
            # compara a chave privada salva com a frase normalizada
            return u.get("chave_pri") == frase_norm

    # se não achou o usuário ou não bateu, é inválida
    return False


def dar_bonus_inicial(chave_pub_destino: str, valor: float = 10.0) -> Dict[str, Optional[int]]:
    """
    Emite moedas a partir da carteira institucional (BANCO_CHAVE_PUB)
    diretamente para a chave pública informada.

    Usado como bônus de novos usuários (por padrão, 10 EDU).
    """
    global moeda_config

    if valor <= 0:
        raise ValueError("valor do bônus deve ser positivo")

    # Controle de emissão (se MoedaConfig implementar)
    if moeda_config is not None and hasattr(moeda_config, "pode_emitir") and hasattr(moeda_config, "registrar_emissao"):
        if not moeda_config.pode_emitir(valor):
            raise ValueError("max_supply excedido ao tentar dar bônus inicial")
        moeda_config.registrar_emissao(valor)

    # Cria transação e bloco
    vc_increment()
    tx = Transacao(
        de_chave_pub=BANCO_CHAVE_PUB,
        para_chave_pub=chave_pub_destino,
        valor=valor,
        vc=vc_get_copy(),
    )

    no_blockchain.registrar_transacao_pendente(tx)
    bloco = no_blockchain.criar_bloco()
    ok = no_blockchain.adicionar_bloco(bloco)
    if not ok:
        raise RuntimeError("falha ao adicionar bloco de bônus inicial")

    return {
        "tx_id": getattr(tx, "id_tx", None),
        "bloco_indice": getattr(bloco, "indice", None),
    }

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
    server_version = "EduCoinRing/0.3"

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
        global leader_info, lider

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

        # MURAL: sempre devolve o JSON do líder (líder + participantes)
        if path == "/mural":
            self._send_json(200, leader_info)
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

        # endpoint continua existindo (mas não é mais chamado pela GUI),
        # pode ser útil para testes manuais.
        if path == "/iniciaeleicao":
            self._start_election()
            self._send_json(200, {"status": "ok", "msg": "eleição iniciada"})
            return

        self.send_response(404)
        self.end_headers()

    # ----------------- POST -----------------

    def do_POST(self):
        global participante, lider, leader_info

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

        # ---------- registro de usuário no líder ----------
        if path == "/registrar_usuario_publico":
            self._handle_registrar_usuario_publico(data)
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
            # atualiza o id do líder no JSON compartilhado
            leader_info["leader_node_id"] = novo_lider
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
        """
        Inicia eleição em anel.
        Agora não é chamado pela GUI: só é disparado internamente,
        por exemplo quando não conseguimos falar com o líder.
        """
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
        global participante, lider, leader_info

        origem = msg.get("origem")
        candidatos: List[str] = msg.get("candidatos", [])

        if NODE_ID not in candidatos:
            candidatos.append(NODE_ID)

        if origem == NODE_ID:
            # escolhe o "maior" ID como líder (string "ip:porta")
            novo_lider = max(candidatos)
            lider = novo_lider
            participante = False
            leader_info["leader_node_id"] = novo_lider
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

    # ----------------- registro de usuário no líder -----------------

    def _handle_registrar_usuario_publico(self, data: Dict):
        """
        Registra informações públicas de um usuário no LÍDER.

        Se este nó NÃO for o líder:
        - Encaminha para o líder (HTTP) usando o ID do líder (ip:porta);
        - Se falhar, dispara eleição e retorna erro 503.

        Se este nó for o líder:
        - Atualiza/adiciona participante em leader_info["participants"];
        - Garante que leader_node_id = NODE_ID;
        - Retorna o JSON completo do líder (leader_info).
        """
        global leader_info, lider

        # payload esperado: id_usuario, nome, chave_pub, ip_no, porta_no
        try:
            id_usuario = data["id_usuario"]
            nome = data["nome"]
            chave_pub = data["chave_pub"]
            ip_no = data["ip_no"]
            porta_no = data["porta_no"]
        except KeyError:
            self._send_json(
                400,
                {"erro": "Campos obrigatórios: id_usuario, nome, chave_pub, ip_no, porta_no"},
            )
            return

        # Se este nó NÃO é o líder, encaminha
        if lider != NODE_ID:
            leader_url = f"http://{lider}" if lider else None
            if not leader_url:
                # sem líder conhecido: inicia eleição e retorna erro
                self._start_election()
                self._send_json(503, {"erro": "Líder desconhecido, eleição iniciada."})
                return

            try:
                resp = requests.post(
                    f"{leader_url}/registrar_usuario_publico",
                    json=data,
                    timeout=5,
                )
                # se der certo, atualiza cópia local de leader_info
                try:
                    new_info = resp.json()
                    if isinstance(new_info, dict):
                        leader_info = new_info
                except Exception:
                    pass

                if resp.ok:
                    self._send_json(200, leader_info)
                else:
                    self._send_json(resp.status_code, resp.json())
                return
            except requests.RequestException:
                # líder aparentemente caiu -> inicia eleição
                self._start_election()
                self._send_json(
                    503,
                    {"erro": "Falha ao contatar líder; eleição iniciada."},
                )
                return

        # Se chegou aqui, este nó é o líder -> grava/atualiza
        participante = {
            "id_usuario": id_usuario,
            "nome": nome,
            "chave_pub": chave_pub,
            "ip_no": ip_no,
            "porta_no": porta_no,
        }

        # evita duplicados por id_usuario
        ja = False
        for p in leader_info["participants"]:
            if p.get("id_usuario") == id_usuario:
                p.update(participante)
                ja = True
                break
        if not ja:
            leader_info["participants"].append(participante)

        # líder garante que o campo leader_node_id está correto
        leader_info["leader_node_id"] = NODE_ID

        self._send_json(200, leader_info)

    # ----------------- transferência de moedas -----------------

    def _handle_transferir(self, data: Dict):
        global moeda_config

        try:
            de = data["de_chave_pub"]        # chave pública do REMETENTE (logado ou banco)
            para = data["para_chave_pub"]    # chave pública do DESTINO
            valor = float(data["valor"])
        except Exception:
            self._send_json(
                400,
                {"erro": "JSON deve conter de_chave_pub, para_chave_pub, valor"},
            )
            return

        if valor <= 0:
            self._send_json(400, {"erro": "valor deve ser positivo"})
            return

        # Caso especial: emissão a partir da carteira do BANCO (bônus, crédito inicial etc.)
        if de == BANCO_CHAVE_PUB:
            try:
                result = dar_bonus_inicial(para, valor)
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "tx_id": result.get("tx_id"),
                        "bloco_indice": result.get("bloco_indice"),
                    },
                )
            except Exception as e:
                logging.exception("Erro em /transferir (bônus do BANCO)")
                self._send_json(400, {"erro": str(e)})
            return

        # Demais casos: transferências normais entre usuários (checa chave privada)
        frase_privada = data.get("frase_privada")
        id_usuario = data.get("id_usuario")  # ID do usuário logado (remetente)

        if not id_usuario or not frase_privada:
            self._send_json(
                400,
                {"erro": "id_usuario e frase_privada são obrigatórios"},
            )
            return

        if not validar_chave_privada(id_usuario, frase_privada):
            self._send_json(403, {"erro": "chave privada incorreta"})
            return

        try:
            vc_increment()
            tx = Transacao(
                de_chave_pub=de,
                para_chave_pub=para,
                valor=valor,
                vc=vc_get_copy(),
            )

            # Assinatura didática (se método existir)
            if frase_privada and hasattr(tx, "assinar"):
                tx.assinar(frase_privada)

            no_blockchain.registrar_transacao_pendente(tx)
            bloco = no_blockchain.criar_bloco()
            ok = no_blockchain.adicionar_bloco(bloco)
            if not ok:
                self._send_json(400, {"erro": "falha ao adicionar bloco"})
                return

            self._send_json(
                200,
                {
                    "status": "ok",
                    "tx_id": tx.id_tx,
                    "bloco_indice": bloco.indice,
                },
            )
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
        logging.info(
            f"Servidor iniciado em {host or '0.0.0.0'}:{port} (NODE_ID={NODE_ID})"
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Encerrando servidor...")
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    run_server()
