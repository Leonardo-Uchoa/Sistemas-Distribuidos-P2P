from classe_usuario import Usuario

class Prof(Usuario):
    def __init__(self, nome, email, matricula, chave_pub, chave_priv, materias , carga_horaria , tem_bolsista):
        super().__init__(nome, email, matricula, chave_pub, chave_priv)

        self.materias = materias
        self.semeste = carga_horaria
        self.eh_bolsista = tem_bolsista
