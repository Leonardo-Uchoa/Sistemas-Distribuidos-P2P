import uuid
import hashlib
from datetime import datetime, timezone
import requests  # usado nos métodos de rede do No

class Pessoa:
    def __init__(self, nome, cpf, email, senha,
                 chave_pri, chave_pub, qtd_moedas=0, categoria=None, id_usuario=None):
        self.id_usuario = id_usuario      # pode ser gerado depois
        self.nome = nome
        self.cpf = cpf
        self.email = email
        self.senha = senha                # idealmente seria um hash
        self.chave_pri = chave_pri
        self.chave_pub = chave_pub
        self.qtd_moedas = qtd_moedas
        self.categoria = categoria        # "ALUNO", "PROFESSOR", "DIRETOR"

    def to_dict(self):
        """Converte o objeto Pessoa em um dicionário (para JSON, etc.)."""
        return {
            "id_usuario": self.id_usuario,
            "nome": self.nome,
            "cpf": self.cpf,
            "email": self.email,
            "senha": self.senha,
            "chave_pri": self.chave_pri,
            "chave_pub": self.chave_pub,
            "qtd_moedas": self.qtd_moedas,
            "categoria": self.categoria,
        }

    @classmethod
    def from_dict(cls, data):
        """Cria uma Pessoa a partir de um dicionário."""
        return cls(
            nome=data["nome"],
            cpf=data["cpf"],
            email=data["email"],
            senha=data["senha"],
            chave_pri=data.get("chave_pri"),
            chave_pub=data["chave_pub"],
            qtd_moedas=data.get("qtd_moedas", 0),
            categoria=data.get("categoria"),
            id_usuario=data.get("id_usuario"),
        )

    def validar_senha(self, senha_em_texto):
        """Compara a senha recebida com a armazenada."""
        return self.senha == senha_em_texto

    def creditar_moedas(self, valor):
        """Adiciona moedas ao saldo."""
        if valor <= 0:
            raise ValueError("Valor a creditar deve ser positivo.")
        self.qtd_moedas += valor

    def debitar_moedas(self, valor):
        """Remove moedas do saldo, se houver saldo suficiente."""
        if valor <= 0:
            raise ValueError("Valor a debitar deve ser positivo.")
        if self.qtd_moedas < valor:
            raise ValueError("Saldo insuficiente.")
        self.qtd_moedas -= valor

    def __repr__(self):
        return f"<{self.__class__.__name__} nome={self.nome!r} categoria={self.categoria!r} moedas={self.qtd_moedas}>"


class Aluno(Pessoa):
    def __init__(self, nome, cpf, email, senha,
                 chave_pri, chave_pub, qtd_moedas,
                 matricula, semestre):

        super().__init__(nome, cpf, email, senha,
                         chave_pri, chave_pub, qtd_moedas,
                         categoria="ALUNO")
        self.matricula = matricula
        self.semestre = semestre

    @classmethod
    def cadastrar_aluno(cls, nome, cpf, email, senha,
                        chave_pri, chave_pub, qtd_moedas,
                        matricula, semestre):
        """Cria e retorna um novo Aluno."""
        return cls(
            nome=nome,
            cpf=cpf,
            email=email,
            senha=senha,
            chave_pri=chave_pri,
            chave_pub=chave_pub,
            qtd_moedas=qtd_moedas,
            matricula=matricula,
            semestre=semestre,
        )

    def to_dict(self):
        """Converte o Aluno (incluindo dados de Pessoa) em dicionário."""
        data = super().to_dict()
        data.update({
            "matricula": self.matricula,
            "semestre": self.semestre,
        })
        return data

    @classmethod
    def from_dict(cls, data):
        """Cria um Aluno a partir de um dicionário."""
        return cls(
            nome=data["nome"],
            cpf=data["cpf"],
            email=data["email"],
            senha=data["senha"],
            chave_pri=data.get("chave_pri"),
            chave_pub=data["chave_pub"],
            qtd_moedas=data.get("qtd_moedas", 0),
            matricula=data["matricula"],
            semestre=data["semestre"],
        )


class Professor(Pessoa):
    def __init__(self, nome, cpf, email, senha,
                 chave_pri, chave_pub, qtd_moedas,
                 matricula, materias, nivel):

        super().__init__(nome, cpf, email, senha,
                         chave_pri, chave_pub, qtd_moedas,
                         categoria="PROFESSOR")
        self.matricula = matricula
        self.materias = materias      # lista de disciplinas
        self.nivel = nivel            # ex: "MESTRE", "DOUTOR"

    def adicionar_materia(self, materia):
        """Adiciona uma disciplina à lista, se ainda não estiver lá."""
        if materia not in self.materias:
            self.materias.append(materia)

    def remover_materia(self, materia):
        """Remove uma disciplina, se existir."""
        if materia in self.materias:
            self.materias.remove(materia)


class Diretor(Pessoa):
    def __init__(self, nome, cpf, email, senha,
                 chave_pri, chave_pub, qtd_moedas,
                 matricula, nivel, mandato):

        super().__init__(nome, cpf, email, senha,
                         chave_pri, chave_pub, qtd_moedas,
                         categoria="DIRETOR")
        self.matricula = matricula
        self.nivel = nivel
        self.mandato = mandato        # ex: (2025, 2027)

    def atualizar_mandato(self, novo_mandato):
        """Atualiza as informações do mandato (ex: (2027, 2031))."""
        self.mandato = novo_mandato

class Transacao:
    def __init__(self, de_chave_pub, para_chave_pub, valor, vc,
                 assinatura=None, id_tx=None, timestamp=None):
        self.id_tx = id_tx or str(uuid.uuid4())  # gera id se não vier
        self.de_chave_pub = de_chave_pub
        self.para_chave_pub = para_chave_pub
        self.valor = valor
        self.vc = vc                    # relógio vetorial no momento da tx
        self.assinatura = assinatura
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        """Converte a transação em dicionário (para JSON / rede)."""
        return {
            "id_tx": self.id_tx,
            "de": self.de_chave_pub,
            "para": self.para_chave_pub,
            "valor": self.valor,
            "vc": self.vc,
            "assinatura": self.assinatura,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data):
        """Cria uma Transacao a partir de um dicionário."""
        return cls(
            de_chave_pub=data["de"],
            para_chave_pub=data["para"],
            valor=data["valor"],
            vc=data.get("vc", {}),
            assinatura=data.get("assinatura"),
            id_tx=data.get("id_tx"),
            timestamp=data.get("timestamp"),
        )

    def eh_valida(self, moeda_config):
        """
        Verifica se a transação é válida de forma básica:
        - valor > 0
        - chaves são autorizadas pela MoedaConfig
        - timestamp dentro do limite de tempo (se houver)
        """
        if self.valor <= 0:
            return False

        if moeda_config and not moeda_config.autorizada(self.de_chave_pub):
            return False

        if moeda_config and not moeda_config.autorizada(self.para_chave_pub):
            return False

        if moeda_config and not moeda_config.eh_valido_timestamp(self.timestamp):
            return False

        return True

    def assinar(self, chave_privada):
        """
        Assinatura 'fake' só para fins didáticos.
        Em uma implementação real, use uma biblioteca de criptografia.
        """
        base = f"{self.de_chave_pub}{self.para_chave_pub}{self.valor}{self.timestamp}"
        self.assinatura = f"ASSINADO-{hash(base + str(chave_privada))}"

    def verificar_assinatura(self, chave_publica):
        """
        Verificação 'fake'. Aqui só checamos se existe assinatura.
        Em produção, deveria verificar criptograficamente.
        """
        return self.assinatura is not None

class MoedaConfig:
    def __init__(
        self,
        nome,
        lista_chaves_pub_autorizadas=None,
        time_limit=None,
        max_supply=100_000,
        id_moeda=None,
        total_emitido=0,
    ):
        self.id_moeda = id_moeda or str(uuid.uuid4())   # id único da moeda
        self.nome = nome                                # "EDUCOIN"
        self.lista_chaves_pub_autorizadas = set(lista_chaves_pub_autorizadas or [])
        self.time_limit = time_limit                    # em segundos ou None
        self.max_supply = max_supply                    # quantidade máxima (ex: 100_000)
        self.total_emitido = total_emitido              # quanto já foi emitido

    # -------------------
    # Regras de participação
    # -------------------
    def autorizada(self, chave_pub):
        """
        Retorna True se a chave pública puder participar.
        Se a lista estiver vazia, considera todas autorizadas.
        """
        if not self.lista_chaves_pub_autorizadas:
            return True
        return chave_pub in self.lista_chaves_pub_autorizadas

    def eh_valido_timestamp(self, timestamp):
        """
        True se o timestamp estiver dentro do limite.
        timestamp deve ser ISO 8601 (datetime.isoformat()).
        Se time_limit for None, sempre retorna True.
        """
        if self.time_limit is None:
            return True

        try:
            ts_datetime = datetime.fromisoformat(timestamp)
        except Exception:
            return False

        if ts_datetime.tzinfo is None:
            ts_datetime = ts_datetime.replace(tzinfo=timezone.utc)

        agora = datetime.now(timezone.utc)
        diferenca = abs((agora - ts_datetime).total_seconds())
        return diferenca <= self.time_limit

    # -------------------
    # Controle de supply
    # -------------------
    def disponivel_para_emitir(self):
        """
        Retorna quanto ainda pode ser criado sem estourar o max_supply.
        """
        return max(self.max_supply - self.total_emitido, 0)

    def pode_emitir(self, quantidade):
        """
        Verifica se é possível emitir 'quantidade' de moedas
        sem ultrapassar o max_supply.
        """
        if quantidade <= 0:
            return False
        return self.total_emitido + quantidade <= self.max_supply

    def registrar_emissao(self, quantidade):
        """
        Registra a emissão de novas moedas, se houver espaço no max_supply.
        Lança ValueError se tentar ultrapassar o limite.
        """
        if not self.pode_emitir(quantidade):
            raise ValueError(
                f"Não é possível emitir {quantidade} {self.nome}. "
                f"Disponível para emissão: {self.disponivel_para_emitir()}."
            )
        self.total_emitido += quantidade

class Bloco:
    def __init__(self, indice, transacoes, hash_anterior,
                 timestamp=None, nonce=0, hash_atual=None):
        self.indice = indice
        self.transacoes = transacoes              # lista de Transacao
        self.hash_anterior = hash_anterior
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.nonce = nonce
        self.hash_atual = hash_atual or self.calcular_hash()

    def calcular_hash(self):
        """Calcula o hash do bloco com base em seus campos principais."""
        tx_str = "".join(sorted(tx.id_tx for tx in self.transacoes))
        base = f"{self.indice}{self.hash_anterior}{self.timestamp}{self.nonce}{tx_str}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def to_dict(self):
        """Converte o bloco para dicionário."""
        return {
            "indice": self.indice,
            "transacoes": [tx.to_dict() for tx in self.transacoes],
            "hash_anterior": self.hash_anterior,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash_atual": self.hash_atual,
        }

    @classmethod
    def from_dict(cls, data):
        """Cria um bloco a partir de um dicionário."""
        transacoes = [Transacao.from_dict(d) for d in data.get("transacoes", [])]
        bloco = cls(
            indice=data["indice"],
            transacoes=transacoes,
            hash_anterior=data["hash_anterior"],
            timestamp=data.get("timestamp"),
            nonce=data.get("nonce", 0),
            hash_atual=data.get("hash_atual"),
        )
        return bloco


class Eleicao:
    def __init__(self, ip_inicial):
        self.ip_inicial = ip_inicial
        self.ip_eleito = None
        self.candidatos = []        # lista de IDs ou IPs
        self.ativo = False

    def iniciar(self, meu_id):
        """Inicia uma nova eleição com o ID deste nó."""
        self.ativo = True
        self.candidatos = [meu_id]
        self.ip_eleito = None

    def registrar_candidato(self, id_no):
        """Adiciona um candidato (ID do nó) à lista, se ainda não estiver lá."""
        if id_no not in self.candidatos:
            self.candidatos.append(id_no)

    def definir_eleito(self):
        """Define como eleito o maior ID da lista de candidatos."""
        if self.candidatos:
            self.ip_eleito = max(self.candidatos)  # ex: maior ID ganha
            self.ativo = False

    def resetar(self):
        """Reseta o estado da eleição."""
        self.candidatos.clear()
        self.ip_eleito = None
        self.ativo = False

    def eh_lider(self, meu_id):
        """Retorna True se meu_id for o nó líder atual."""
        return self.ip_eleito == meu_id

    def esta_ativa(self):
        """Retorna True se a eleição ainda estiver em andamento."""
        return self.ativo


class No:
    def __init__(self, ip, porta, usuario, eleicao, moeda_config=None):
        self.ip = ip
        self.porta = porta
        self.usuario = usuario          # Pessoa/Aluno/Professor/Diretor
        self.eleicao = eleicao          # objeto Eleicao
        self.peers = []                 # lista de (ip, porta)
        self.blockchain = []            # lista de Bloco
        self.transacoes_pendentes = []  # lista de Transacao
        self.moeda_config = moeda_config
        self.id_no = f"{ip}:{porta}"
        self.lider_atual = None

    # -----------------------
    # Métodos de rede / P2P
    # -----------------------

    def adicionar_peer(self, ip, porta):
        """Adiciona um peer (ip, porta) à lista, se ainda não existir."""
        peer = (ip, porta)
        if peer not in self.peers and peer != (self.ip, self.porta):
            self.peers.append(peer)

    def remover_peer(self, ip, porta):
        """Remove um peer (ip, porta) da lista, se existir."""
        peer = (ip, porta)
        if peer in self.peers:
            self.peers.remove(peer)

    def listar_peers(self):
        """Retorna uma cópia da lista de peers."""
        return list(self.peers)

    def enviar_para_peer(self, peer, path, payload, metodo="POST", timeout=3.0):
        """
        Envia uma requisição HTTP simples para um peer.
        path exemplo: '/tx', '/eleicao', '/eleito'
        """
        ip, porta = peer
        url = f"http://{ip}:{porta}{path}"
        try:
            if metodo.upper() == "POST":
                r = requests.post(url, json=payload, timeout=timeout)
            else:
                r = requests.get(url, params=payload, timeout=timeout)
            return r.status_code == 200
        except Exception:
            return False

    def broadcast(self, path, payload, metodo="POST"):
        """Envia a mesma mensagem para todos os peers."""
        for peer in self.peers:
            self.enviar_para_peer(peer, path, payload, metodo=metodo)

    # -----------------------
    # Transações / Blockchain
    # -----------------------

    def registrar_transacao_pendente(self, tx):
        """Registra uma transação pendente (se ainda não estiver na lista)."""
        if any(existing.id_tx == tx.id_tx for existing in self.transacoes_pendentes):
            return
        self.transacoes_pendentes.append(tx)

    def enviar_transacao(self, tx):
        """Valida (se possível), registra e propaga a transação para a rede."""
        if self.moeda_config and not tx.eh_valida(self.moeda_config):
            raise ValueError("Transação inválida para esta moeda.")
        self.registrar_transacao_pendente(tx)
        self.broadcast("/tx", tx.to_dict())

    def receber_transacao(self, tx_dict):
        """Recebe uma transação (geralmente via HTTP), valida e registra."""
        tx = Transacao.from_dict(tx_dict)
        if self.moeda_config and not tx.eh_valida(self.moeda_config):
            return
        self.registrar_transacao_pendente(tx)

    def criar_bloco(self):
        """
        Cria um novo bloco com as transações pendentes.
        Normalmente chamado apenas pelo líder.
        """
        indice = len(self.blockchain)
        if self.blockchain:
            hash_anterior = self.blockchain[-1].hash_atual
        else:
            hash_anterior = "0" * 64  # hash do bloco gênesis

        transacoes = self.transacoes_pendentes.copy()
        self.transacoes_pendentes.clear()

        bloco = Bloco(
            indice=indice,
            transacoes=transacoes,
            hash_anterior=hash_anterior,
        )
        return bloco

    def adicionar_bloco(self, bloco):
        """
        Valida ligações básicas e adiciona o bloco à blockchain.
        Retorna True se deu certo, False caso contrário.
        """
        if self.blockchain:
            ultimo = self.blockchain[-1]
            if bloco.hash_anterior != ultimo.hash_atual:
                return False
            if bloco.indice != ultimo.indice + 1:
                return False
        else:
            # primeiro bloco deve ser índice 0
            if bloco.indice != 0:
                return False

        # valida o hash
        if bloco.calcular_hash() != bloco.hash_atual:
            return False

        self.blockchain.append(bloco)
        return True

    def validar_blockchain(self):
        """Valida a cadeia inteira (hashes e ligações)."""
        for i, bloco in enumerate(self.blockchain):
            if bloco.calcular_hash() != bloco.hash_atual:
                return False
            if i == 0:
                continue
            anterior = self.blockchain[i - 1]
            if bloco.hash_anterior != anterior.hash_atual:
                return False
        return True

    def calcular_saldo(self, chave_pub):
        """Calcula o saldo de uma chave pública percorrendo todos os blocos."""
        saldo = 0.0
        for bloco in self.blockchain:
            for tx in bloco.transacoes:
                if tx.de_chave_pub == chave_pub:
                    saldo -= tx.valor
                if tx.para_chave_pub == chave_pub:
                    saldo += tx.valor
        return saldo

    def obter_historico(self, chave_pub):
        """Retorna a lista de transações que envolvem a chave pública."""
        historico = []
        for bloco in self.blockchain:
            for tx in bloco.transacoes:
                if tx.de_chave_pub == chave_pub or tx.para_chave_pub == chave_pub:
                    historico.append(tx)
        return historico

    # -----------------------
    # Eleição
    # -----------------------

    def iniciar_eleicao(self):
        """Inicia o processo de eleição e propaga a mensagem para os peers."""
        self.eleicao.iniciar(self.id_no)
        msg = {
            "tipo": "ELEICAO",
            "origem": self.id_no,
            "candidatos": self.eleicao.candidatos,
        }
        self.broadcast("/eleicao", msg)

    def processar_mensagem_eleicao(self, msg):
        """
        Processa uma mensagem de eleição recebida.
        A ideia é típica de algoritmo de eleição em anel:
        - acumula candidatos
        - quando volta na origem, decide o líder
        """
        origem = msg.get("origem")
        candidatos = msg.get("candidatos", [])

        # registra candidatos recebidos
        for c in candidatos:
            self.eleicao.registrar_candidato(c)

        # também registra este nó
        self.eleicao.registrar_candidato(self.id_no)

        if origem == self.id_no:
            # mensagem voltou para o nó inicial -> decide o líder
            self.eleicao.definir_eleito()
            self.atualizar_lider(self.eleicao.ip_eleito)

            payload = {
                "tipo": "ELEITO",
                "lider": self.lider_atual,
            }
            self.broadcast("/eleito", payload)
        else:
            # repassa para frente com a lista atualizada
            novo_msg = {
                "tipo": "ELEICAO",
                "origem": origem,
                "candidatos": self.eleicao.candidatos,
            }
            self.broadcast("/eleicao", novo_msg)

    def atualizar_lider(self, novo_lider):
        """Atualiza o líder atual do ponto de vista deste nó."""
        self.lider_atual = novo_lider
        self.eleicao.ip_eleito = novo_lider
        self.eleicao.ativo = False
