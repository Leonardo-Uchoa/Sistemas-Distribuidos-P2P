import hashlib
import getpass
import hmac
from typing import Dict, Tuple


def sha256(s: str) -> str:
    """Retorna o SHA-256 hexadecimal da string passada."""
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def create_key_priv() -> str:
    """
    Pede ao usuário a 'private key' (oculta) e retorna seu hash SHA-256.
    Uso simples: para testes. Em produção use um gerador de chaves/assinaturas.
    """
    raw = getpass.getpass('Digite sua chave private: ')
    return sha256(raw)


def create_key_pub() -> str:
    """
    Pede ao usuário a 'public key' (visível) e retorna seu hash SHA-256.
    (normalizo pra o mesmo formato usado nas comparações)
    """
    raw = input('Digite sua chave public: ').strip()
    return sha256(raw)


def send_coin(priv_key_hash: str, coin_id: str, pub_key_dest_hash: str) -> Tuple[bool, Dict]:
    """
    Fluxo de envio de moeda:
    - pergunta confirmação Y/N
    - pede validação com private key (oculta)
    - compara de forma segura (hashes)
    Retorna (sucesso, transacao_dict)
    """
    print('Deseja enviar moedas? [Y/N]')
    val = input().strip().lower()

    if val == 'y':
        val_key_raw = getpass.getpass("Valide com sua private key (entrada oculta): ")
        val_key_hash = sha256(val_key_raw)

        # comparação resistente a timing attacks
        if hmac.compare_digest(priv_key_hash, val_key_hash):
            tx = {
                'action': 'send',
                'coin_id': coin_id,
                'from': priv_key_hash,
                'to': pub_key_dest_hash
            }
            print(f"Moeda id:{coin_id} enviada para key destino {pub_key_dest_hash}!")
            return True, tx
        else:
            print('Private key inválida. Transação cancelada.')
            return False, {}

    elif val == 'n':
        print("Operação cancelada. Até mais!")
        return False, {}
    else:
        print("Entrada inválida. Use 'Y' ou 'N'.")
        return False, {}


def receive_coin(pub_key_hash: str, coin_id: str) -> bool:
    """
    Fluxo de recebimento:
    - pede que usuário digite sua chave pública
    - compara o hash com o `pub_key_hash` esperado
    Retorna True se o usuário corresponde à chave pública (aceita a moeda).
    """
    print("Você recebeu uma moeda.")
    val_pub_raw = input("Digite sua chave publica: ").strip()
    val_pub_hash = sha256(val_pub_raw)

    if hmac.compare_digest(pub_key_hash, val_pub_hash):
        print(f"Agora a moeda id:{coin_id} pertence a você.")
        return True
    else:
        print("A moeda não corresponde a você, tente novamente com a chave certa.")
        return False


if __name__ == '__main__':
    # exemplo de uso local/teste:
    print("=== Exemplo local ===")
    # criar chaves (em um app real a chave privada NÃO deve ser alfabetizada manualmente)
    priv = create_key_priv()
    pub = create_key_pub()

    print("\nHashes (armazenar esses valores para testes):")
    print("private_hash:", priv)
    print("public_hash :", pub)

    # testar envio
    success, tx = send_coin(priv, id_moeda := "MOEDA123", pub)
    if success:
        print("TX gerada:", tx)
        # simular recebimento no destinatário:
        receive_coin(pub, id_moeda)
