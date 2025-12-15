from classe_usuario import Usuario

class Aluno(Usuario):
    def __init__(self, nome, email, matricula, chave_pub, chave_priv, nota , semestre , eh_bolsista):
        super().__init__(nome, email, matricula, chave_pub, chave_priv)

        self.nota = nota
        self.semeste = semestre
        self.eh_bolsista = eh_bolsista

