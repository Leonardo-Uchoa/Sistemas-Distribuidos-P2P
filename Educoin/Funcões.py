# Funcões.py
"""
Nó do anel com eleição, mural distribuído e relógio vetorial,
 + integração com as classes de blockchain/Educoin do arquivo Classes.py.
"""

import http.server
import socketserver
import json
import requests
import threading
import uuid
import logging
from typing import List, Dict, Optional
import time
import random
from urllib.parse import urlparse, parse_qs

# >>> IMPORTA AS CLASSES DE MODELO <<<
from Classes import No, Eleicao as EleicaoLogica, MoedaConfig, Transacao, Aluno

# ========== CONFIG ==========
NODE_ID: int = random.randint(1, 10000)  # ID aleatório do nó
PORT: int = 8001                         # mude se precisar

# URL do próximo nó no anel (ajuste conforme topologia)
noh_conectado: str = "http://10.80.40.253:8000"

lider: Optional[int] = None
participante: bool = False
mural: List[Dict] = []  # mural compartilhado (lista de mensagens únicas)
# ============================

lock = threading.Lock()
TIMEOUT_S = 3
REQUEST_RETRIES = 2   # tentativas de POST
SYNC_INTERVAL_S = 5   # intervalo para o líder sincronizar com o próximo nó

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Reutilizar sessão HTTP
session = requests.Session()

# ========== RELÓGIO VETORIAL ==========
# dicionário esparso {node_id: counter}
vector_clock: Dict[int, int] = {}


def vc_increment():
    """Incrementa a entrada do NODE_ID no relógio vetorial (evento local/envio)."""
    with lock:
        vector_clock[NODE_ID] = vector_clock.get(NODE_ID, 0) + 1
        logging.debug(f"VC incrementado: {vector_clock}")


def vc_merge(received_vc: Optional[Dict]):
    """
    Faz o merge entre o vector clock local e o recebido (max por posição),
    e depois incrementa o relógio local (regra de recebimento).
    """
    if not received_vc:
        return

    with lock:
        for k_str, v in received_vc.items():
            # chaves podem vir como string pelo JSON
            try:
                k = int(k_str)
            except Exception:
                continue
            if not isinstance(v, int):
                try:
                    v = int(v)
                except Exception:
                    continue
            current = vector_clock.get(k, 0)
            if v > current:
                vector_clock[k] = v

        # incremento local depois de receber
        vector_clock[NODE_ID] = vector_clock.get(NODE_ID, 0) + 1
        logging.debug(f"VC mesclado e incrementado após recebimento: {vector_clock}")


def vc_get_copy() -> Dict[str, int]:
    """Retorna uma cópia do vector clock com chaves string (pronto para JSON)."""
    with lock:
        return {str(k): int(v) for k, v in vector_clock.items()}


# =====================================================
#        INTEGRAÇÃO COM Classes.py (EduCoin / No)
# =====================================================

# Configuração básica da moeda EDUCOIN (máx 100.000)
moeda_config = MoedaConfig(nome="EDUCOIN", max_supply=100_000)

# Usuário local deste nó (por enquanto um Aluno "fake" só pra ter chave)
usuario_local = Aluno.cadastrar_aluno(
    nome=f"Aluno-{NODE_ID}",
    cpf="00000000000",
    email=f"aluno{NODE_ID}@if.edu",
    senha="123",
    chave_pri=f"PRI-{NODE_ID}",
    chave_pub=f"PUB-{NODE_ID}",
    qtd_moedas=0,
    matricula=str(NODE_ID),
    semestre=1,
)

# Objeto Eleicao lógico (não é a mesma eleição do anel de mural,
# mas pode ser usado futuramente se você quiser unificar)
eleicao_logica = EleicaoLogica(ip_inicial=f"http://127.0.0.1:{PORT}")

# Nó blockchain associado a este processo
no_blockchain = No(
    ip="127.0.0.1",
    porta=PORT,
    usuario=usuario_local,
    eleicao=eleicao_logica,
    moeda_config=moeda_config,
)

# Adiciona o próximo nó do anel como peer do nó blockchain (para /tx etc.)
try:
    parsed_next = urlparse(noh_conectado)
    host_next = parsed_next.hostname or "127.0.0.1"
    port_next = parsed_next.port or 8000
    no_blockchain.adicionar_peer(host_next, port_next)
except Exception:
    logging.warning("Não foi possível registrar noh_conectado como peer do No blockchain")

# =====================================================
#  EVENTOS ACADÊMICOS → GERAÇÃO DE TRANSACÕES EDUCOIN
# =====================================================

# "Carteira institucional" (de onde as recompensas saem e para onde
# os pagamentos de marketplace entram). Em um projeto maior,
# isso poderia ser uma Pessoa/Diretor com chaves próprias.
CHAVE_PUB_INSTITUCIONAL = "PUB-INSTITUICAO"
CHAVE_PRI_INSTITUCIONAL = "PRI-INSTITUICAO"  # aqui é simbólica

def calcular_recompensa_monitoria(duracao_horas, feedback_nota=None):
    """
    Calcula a quantidade de EduCoin por uma monitoria.
    Regra simples: 10 moedas por hora, com pequeno ajuste por feedback (0–10).
    """
    dur = max(duracao_horas, 0)
    base = dur * 10.0
    if feedback_nota is not None:
        try:
            fb = float(feedback_nota)
            # Ajuste suave: nota 10 -> +20%, nota 0 -> -20%
            fator = 1.0 + (fb - 5.0) / 25.0
            if fator < 0.5:
                fator = 0.5
            if fator > 1.5:
                fator = 1.5
            base *= fator
        except Exception:
            pass
    return round(base, 2)


def registrar_monitoria(aluno_monitor, aluno_atendido, duracao_horas, descricao=""):
    """
    Gera uma transação de recompensa de monitoria para o aluno_monitor.
    - Emite EduCoin (respeitando o max_supply).
    - Cria Transacao da carteira institucional -> carteira do monitor.
    - Envia a transação para a rede via no_blockchain.
    Retorna o objeto Transacao.
    """
    valor = calcular_recompensa_monitoria(duracao_horas)

    # Garante que ainda há supply disponível
    if not moeda_config.pode_emitir(valor):
        raise ValueError("Supply de EduCoin esgotado para recompensas de monitoria.")

    moeda_config.registrar_emissao(valor)

    # Atualiza relógio vetorial e cria transação
    vc_increment()
    tx = Transacao(
        de_chave_pub=CHAVE_PUB_INSTITUCIONAL,
        para_chave_pub=aluno_monitor.chave_pub,
        valor=valor,
        vc=vc_get_copy(),
    )

    # (Descrição/aluno_atendido podem ser guardados em outra estrutura, se quiser.)
    no_blockchain.enviar_transacao(tx)
    return tx


def calcular_recompensa_nota(nota):
    """
    Converte uma nota (0–10) em recompensa em EduCoin.
    Exemplo: nota 6 -> 0 moedas; nota 10 -> 40 moedas (linear).
    """
    try:
        n = float(nota)
    except Exception:
        return 0.0
    if n < 6.0:
        return 0.0
    if n > 10.0:
        n = 10.0
    # Mapeia [6,10] -> [0,40]
    recompensa = (n - 6.0) * 10.0
    return round(recompensa, 2)


def registrar_nota(aluno, disciplina, nota):
    """
    Se a nota for suficiente, gera uma transação de recompensa para o aluno
    baseada em calcular_recompensa_nota.
    Retorna a Transacao ou None se não houver recompensa.
    """
    valor = calcular_recompensa_nota(nota)
    if valor <= 0:
        return None

    if not moeda_config.pode_emitir(valor):
        raise ValueError("Supply de EduCoin esgotado para recompensas de notas.")

    moeda_config.registrar_emissao(valor)

    vc_increment()
    tx = Transacao(
        de_chave_pub=CHAVE_PUB_INSTITUCIONAL,
        para_chave_pub=aluno.chave_pub,
        valor=valor,
        vc=vc_get_copy(),
    )

    no_blockchain.enviar_transacao(tx)
    return tx


def calcular_recompensa_evento(tipo_evento):
    """
    Retorna a recompensa padrão para diferentes tipos de evento.
    Você pode ajustar o dicionário conforme o projeto.
    """
    tabela = {
        "palestra": 20.0,
        "workshop": 30.0,
        "maratona_programacao": 50.0,
        "projeto_extensao": 40.0,
        "outro": 10.0,
    }
    return tabela.get(tipo_evento, tabela["outro"])


def registrar_participacao_evento(aluno, tipo_evento, descricao=""):
    """
    Gera recompensa para participação em evento acadêmico.
    """
    valor = calcular_recompensa_evento(tipo_evento)

    if not moeda_config.pode_emitir(valor):
        raise ValueError("Supply de EduCoin esgotado para recompensas de eventos.")

    moeda_config.registrar_emissao(valor)

    vc_increment()
    tx = Transacao(
        de_chave_pub=CHAVE_PUB_INSTITUCIONAL,
        para_chave_pub=aluno.chave_pub,
        valor=valor,
        vc=vc_get_copy(),
    )

    no_blockchain.enviar_transacao(tx)
    return tx


def registrar_material_compartilhado(aluno, link, tipo_material="apostila"):
    """
    Recompensa por compartilhar material (apostila, vídeo, lista de exercícios...).
    Exemplo simples: 15 moedas fixas por material.
    """
    valor = 15.0

    if not moeda_config.pode_emitir(valor):
        raise ValueError("Supply de EduCoin esgotado para recompensas de material.")

    moeda_config.registrar_emissao(valor)

    vc_increment()
    tx = Transacao(
        de_chave_pub=CHAVE_PUB_INSTITUCIONAL,
        para_chave_pub=aluno.chave_pub,
        valor=valor,
        vc=vc_get_copy(),
    )

    no_blockchain.enviar_transacao(tx)
    return tx


def registrar_projeto(aluno, titulo, tipo_projeto="pesquisa"):
    """
    Recompensa por participação em projeto (pesquisa, extensão, TCC, etc.).
    Aqui usamos uma recompensa padrão de 50 moedas.
    """
    valor = 50.0

    if not moeda_config.pode_emitir(valor):
        raise ValueError("Supply de EduCoin esgotado para recompensas de projetos.")

    moeda_config.registrar_emissao(valor)

    vc_increment()
    tx = Transacao(
        de_chave_pub=CHAVE_PUB_INSTITUCIONAL,
        para_chave_pub=aluno.chave_pub,
        valor=valor,
        vc=vc_get_copy(),
    )

    no_blockchain.enviar_transacao(tx)
    return tx


# =====================================================
#             MARKETPLACE DE BENEFÍCIOS
# =====================================================

# Tabela simples de benefícios disponíveis
BENEFICIOS = {
    "lab_extra": {
        "nome": "Horas extras de laboratório",
        "custo": 50.0,
    },
    "mentoria": {
        "nome": "Sessão de mentoria individual",
        "custo": 80.0,
    },
    "prioridade_tema": {
        "nome": "Prioridade na escolha de tema de projeto",
        "custo": 40.0,
    },
}

# Histórico de resgates (em memória)
RESGATES = []


def listar_beneficios():
    """
    Retorna a lista de benefícios disponíveis no marketplace.
    """
    return [
        {"id": bid, "nome": info["nome"], "custo": info["custo"]}
        for bid, info in BENEFICIOS.items()
    ]


def resgatar_beneficio(chave_pub, beneficio_id):
    """
    Cria uma transação do aluno -> instituição para "pagar" um benefício.
    - Verifica se o benefício existe.
    - Verifica se há saldo suficiente (na blockchain).
    - Gera Transacao da carteira do aluno para a institucional.
    - Registra o resgate em RESGATES.
    Retorna um dicionário com os dados do resgate.
    """
    if beneficio_id not in BENEFICIOS:
        raise ValueError("Benefício inexistente.")

    beneficio = BENEFICIOS[beneficio_id]
    custo = beneficio["custo"]

    # Verifica saldo do aluno
    saldo = no_blockchain.calcular_saldo(chave_pub)
    if saldo < custo:
        raise ValueError(
            f"Saldo insuficiente. Saldo atual: {saldo}, custo do benefício: {custo}."
        )

    # Cria transação aluno -> instituição
    vc_increment()
    tx = Transacao(
        de_chave_pub=chave_pub,
        para_chave_pub=CHAVE_PUB_INSTITUCIONAL,
        valor=custo,
        vc=vc_get_copy(),
    )
    no_blockchain.enviar_transacao(tx)

    registro = {
        "beneficio_id": beneficio_id,
        "beneficio_nome": beneficio["nome"],
        "chave_pub": chave_pub,
        "custo": custo,
        "tx_id": tx.id_tx,
        "timestamp": tx.timestamp,
    }
    RESGATES.append(registro)
    return registro


def listar_resgates(chave_pub=None):
    """
    Lista todos os resgates ou apenas os de uma chave pública específica.
    """
    if chave_pub is None:
        return list(RESGATES)
    return [r for r in RESGATES if r["chave_pub"] == chave_pub]


# =====================================================
#             REDE: async_post + sync_with_next_once
# =====================================================

def async_post(url: str, payload: dict, max_retries: int = REQUEST_RETRIES):
    """
    Faz POST assíncrono com retries básicos e checagem de status HTTP.
    Não retorna nada; apenas loga erros.
    """
    payload_snapshot = dict(payload) if payload is not None else {}

    # anexa VC atual se não houver 'vc' no payload
    if "vc" not in payload_snapshot:
        payload_snapshot["vc"] = vc_get_copy()

    def _run():
        for attempt in range(1, max_retries + 1):
            try:
                resp = session.post(url, json=payload_snapshot, timeout=TIMEOUT_S)
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
    """
    Busca /mural do nó destino e incorpora mensagens novas no mural local.
    Retorna o número de mensagens adicionadas.
    Se destino não for fornecido, usa noh_conectado.
    Depois de adicionar, replica as mensagens novas para o destino (propagar unificação).
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
                    mural.append(
                        {
                            "id": mid,
                            "autor": msg.get("autor"),
                            "texto": msg.get("texto", ""),
                            "vc": msg.get("vc"),
                        }
                    )
                    new_msgs.append(
                        {
                            "id": mid,
                            "autor": msg.get("autor"),
                            "texto": msg.get("texto", ""),
                            "vc": msg.get("vc"),
                        }
                    )
                    added += 1

        if added:
            logging.info(f"Sincronização: adicionadas {added} mensagens do {destino}")
            # replicar mensagens novas para o próximo nó para propagar unificação
            for msg in new_msgs:
                async_post(destino + "/mural", msg)

    except requests.RequestException as e:
        logging.warning(f"Falha ao sincronizar com {destino}: {e}")
    except ValueError:
        logging.warning("Resposta JSON inválida ao sincronizar mural")

    return added


# ========== SERVIDOR HTTP ==========

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

    # ------------- GET -------------
    def do_GET(self):
        global participante, mural, lider

        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # --------- API BLOCKCHAIN: SALDO ----------
        if path == "/saldo":
            chave = qs.get("chave_pub", [None])[0]
            if not chave:
                self._send_json(400, {"erro": "Parâmetro 'chave_pub' obrigatório"})
                return
            saldo = no_blockchain.calcular_saldo(chave)
            self._send_json(200, {"chave_pub": chave, "saldo": saldo})
            return

        # --------- API BLOCKCHAIN: CADEIA ----------
        if path == "/blockchain":
            chain = [b.to_dict() for b in no_blockchain.blockchain]
            self._send_json(200, chain)
            return

        # --------- FUNCIONALIDADES DO ANEL ----------
        if path.startswith("/iniciaeleicao"):
            with lock:
                participante = True
                destino = noh_conectado
            vc_increment()
            async_post(destino + "/eleicao", {"candidato": NODE_ID})
            self._send_json(202, {"mensagem": "Eleição iniciada", "meu_id": NODE_ID})

        elif path.startswith("/leader"):
            with lock:
                atual = lider
            self._send_json(200, {"leader": atual})

        elif path.startswith("/mural"):
            with lock:
                mural_copy = list(mural)
            self._send_json(200, mural_copy)

        else:
            self.send_response(404)
            self.end_headers()

    # ------------- POST -------------
    def do_POST(self):
        global participante, lider, mural

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

        # se veio vc no payload, mescla (recebimento)
        try:
            incoming_vc = data.get("vc")
            if incoming_vc:
                vc_merge(incoming_vc)
        except Exception as e:
            logging.warning(f"Erro ao mesclar VC recebido: {e}")

        parsed = urlparse(self.path)
        path = parsed.path

        # -------- API BLOCKCHAIN: /tx (receber transação EduCoin) --------
        if path == "/tx":
            try:
                # Usa a lógica do No (validação + pendente) a partir do dicionário
                no_blockchain.receber_transacao(data)
            except Exception as e:
                self._send_json(400, {"erro": f"Transação inválida: {e}"})
                return
            self._send_json(201, {"status": "ok"})
            return

        # -------- /eleicao --------
        if path.startswith("/eleicao"):
            raw_cid = data.get("candidato")
            try:
                cid = int(raw_cid)
            except (TypeError, ValueError):
                self._send_json(400, {"erro": "campo 'candidato' inválido"})
                return

            # se o candidato sou eu -> sou líder
            if cid == NODE_ID:
                with lock:
                    lider_local = NODE_ID
                    destino = noh_conectado
                    participante = False
                    lider = lider_local
                vc_increment()
                async_post(destino + "/eleito", {"eleito": NODE_ID})
                self._send_json(200, {"mensagem": "Sou líder", "leader": NODE_ID})
                return

            # encaminha maior ID
            with lock:
                participante = True
                forward_id = NODE_ID if NODE_ID > cid else cid
                destino = noh_conectado

            vc_increment()
            async_post(destino + "/eleicao", {"candidato": forward_id})
            self._send_json(202, {"mensagem": "Eleição encaminhada", "candidato": forward_id})
            return

        # -------- /eleito --------
        elif path.startswith("/eleito"):
            raw_eleito = data.get("eleito")
            try:
                eleito = int(raw_eleito)
            except (TypeError, ValueError):
                self._send_json(400, {"erro": "campo 'eleito' inválido"})
                return

            with lock:
                lider_local = eleito
                lider = eleito
                participante = False
                sou_lider = (NODE_ID == eleito)
                destino = noh_conectado

            if not sou_lider:
                vc_increment()
                async_post(destino + "/eleito", {"eleito": eleito})

            self._send_json(200, {"mensagem": "Líder reconhecido", "leader": eleito})
            return

        # -------- /mural --------
        elif path.startswith("/mural"):
            texto = data.get("texto", "")
            msg_id = data.get("id") or str(uuid.uuid4())
            autor = data.get("autor", NODE_ID)

            if not isinstance(texto, str) or len(texto) > 5000:
                self._send_json(400, {"erro": "texto inválido ou muito grande"})
                return

            msg = {"id": str(msg_id), "autor": autor, "texto": texto, "vc": data.get("vc")}

            with lock:
                if any(m["id"] == msg["id"] for m in mural):
                    logging.info("Mensagem já existe no mural: %s", msg["id"])
                    self._send_json(200, msg)
                    try:
                        destino = noh_conectado
                        vc_increment()
                        async_post(destino + "/sync_request", {"origin": NODE_ID})
                    except Exception:
                        pass
                    return
                mural.append(msg)

            with lock:
                is_lider = (lider == NODE_ID)
                destino = noh_conectado

            if is_lider:
                vc_increment()
                async_post(destino + "/mural", msg)
            else:
                try:
                    vc_increment()
                    async_post(destino + "/sync_request", {"origin": NODE_ID})
                except Exception:
                    pass

            self._send_json(201, msg)
            return

        # -------- /sync_request --------
        elif path.startswith("/sync_request"):
            with lock:
                is_lider = (lider == NODE_ID)
                destino = noh_conectado

            if is_lider:
                added = sync_with_next_once(destino)
                self._send_json(200, {"mensagens_adicionadas": added})
            else:
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


# ========== LOOP DE SINCRONIZAÇÃO DO LÍDER ==========

def sync_with_next_loop():
    """
    Loop em background: se este nó for líder, periodicamente chama
    sync_with_next_once(destino) para unificar o mural com o próximo nó.
    """
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


# ========== MAIN / EXECUÇÃO ==========

def run_server(host: str = "", port: int = PORT):
    httpd = ThreadingTCPServer((host, port), NossoHandler)
    logging.info(f"Node {NODE_ID} servindo em {host or '0.0.0.0'}:{port}")

    # thread do loop de sincronização do líder
    sync_thread = threading.Thread(target=sync_with_next_loop, daemon=True)
    sync_thread.start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Encerrando servidor...")
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    run_server()
