from classe_usuario import Usuario

class diretor(Usuario):
    def __init__(self, nome, email, matricula, chave_pub, chave_priv, materias , carga_horaria , tem_bolsista, mandato):
        super().__init__(nome, email, matricula, chave_pub, chave_priv)

        self.materias = materias
        self.semeste = carga_horaria
        self.eh_bolsista = tem_bolsista
        self.mandato = mandato