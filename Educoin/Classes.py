class Pessoa:
    def __init__(self, nome, cpf, email, senha,
                 chave_pri, chave_pub, qtd_moedas=0, categoria=None, id_usuario=None):
        self.id_usuario = id_usuario      # pode ser gerado depois
        self.nome = nome
        self.cpf = cpf
        self.email = email
        self.senha = senha                # idealmente seria um hash, mas ok p/ trabalho
        self.chave_pri = chave_pri
        self.chave_pub = chave_pub
        self.qtd_moedas = qtd_moedas
        self.categoria = categoria        # "ALUNO", "PROFESSOR", "DIRETOR"


class Aluno(Pessoa):
    def __init__(self, nome, cpf, email, senha,
                 chave_pri, chave_pub, qtd_moedas,
                 matricula, semestre):

        super().__init__(nome, cpf, email, senha,
                         chave_pri, chave_pub, qtd_moedas,
                         categoria="ALUNO")
        self.matricula = matricula
        self.semestre = semestre


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


class Transacao:
    def __init__(self, de_chave_pub, para_chave_pub, valor, vc, assinatura=None, id_tx=None, timestamp=None):
        self.id_tx = id_tx              # pode ser uuid
        self.de_chave_pub = de_chave_pub
        self.para_chave_pub = para_chave_pub
        self.valor = valor
        self.vc = vc                    # relógio vetorial no momento da tx
        self.assinatura = assinatura
        self.timestamp = timestamp

class MoedaConfig:
    def __init__(self, nome, lista_chaves_pub_autorizadas, time_limit):
        self.nome = nome                # "EDUCOIN"
        self.lista_chaves_pub_autorizadas = lista_chaves_pub_autorizadas
        self.time_limit = time_limit    # validade de algo, se fizer sentido


class Eleicao:
    def __init__(self, ip_inicial):
        self.ip_inicial = ip_inicial
        self.ip_eleito = None
        self.candidatos = []        # lista de IDs ou IPs
        self.ativo = False

    def iniciar(self, meu_id):
        self.ativo = True
        self.candidatos = [meu_id]

    def registrar_candidato(self, id_no):
        if id_no not in self.candidatos:
            self.candidatos.append(id_no)

    def definir_eleito(self):
        if self.candidatos:
            self.ip_eleito = max(self.candidatos)  # ex: maior ID ganha
            self.ativo = False

class Nó:
    def __init__(self, ip, porta, usuario, eleicao):
        self.ip = ip
        self.porta = porta
        self.usuario = usuario
        self.eleicao = eleicao
        self.peers = []
        self.blockchain = []