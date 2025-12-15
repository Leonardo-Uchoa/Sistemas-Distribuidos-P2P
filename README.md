# Educoin - Rede P2P Acadêmica

Este repositório contém o protótipo **Educoin**, uma criptomoeda de uso escolar construída sobre conceitos de Sistemas Distribuídos. Após esta iteração o sistema oferece:

- **Gestão completa de usuários/contas** com campos obrigatórios (nome, CPF, e-mail, categoria) e autenticação por senha.
- **Geração e armazenamento formal de chaves**: cada cadastro cria automaticamente chave pública/privada e gera um arquivo JSON exportável (pasta `data/exports`).
- **Ledger persistente + blockchain**: toda transferência gera um bloco com hash encadeado, guardado em `data/ledger.json`. Logs individuais por conta são gravados em CSV (pasta `data/logs`).
- **Interface web com login** para criar contas (somente líder), transferir moedas autenticado, baixar log/export e visualizar a blockchain.
- **API FastAPI** com endpoints de autenticação, transações, blockchain e replicação entre nós. Seguidores encaminham operações ao líder automaticamente.
- **Stack Docker Compose** que sobe líder + 2 seguidores + serviço de ring legado (para eleição Lamport/Bully). Cada serviço possui volume próprio.

## Estrutura

```
.
├── educoin_project
│   ├── app
│   │   ├── auth.py          # tokens + hashing de credenciais
│   │   ├── blockchain.py    # representação de blocos
│   │   ├── ledger.py        # regras de usuários, transferências, logs
│   │   ├── models.py        # dataclasses de domínio
│   │   ├── p2p.py           # proxy e replicação
│   │   ├── storage.py       # persistência JSON thread-safe
│   │   ├── templates/index.html  # UI
│   │   └── main.py          # FastAPI
│   ├── Dockerfile
│   └── requirements.txt
├── client_ring.py           # serviço de eleição/relógio Lamport
├── docker-compose.yml       # sobe líder, seguidores e nós de anel
└── README.md
```

## Executando com Docker Compose

1. **Build e subida**
   ```bash
   docker compose up --build
   ```
   Serviços:
   - `educoin-leader` → FastAPI líder em `http://localhost:8000`
   - `educoin-node-1` → seguidor (`http://localhost:8001`)
   - `educoin-node-2` → seguidor (`http://localhost:8002`)
   - `ring-node-a/b/c` → nós herdados do `client_ring.py` responsáveis pela eleição Bully + relógio Lamport (cada um expõe portas 8101-8103) replicando estado do líder.

2. **Login**
   - Acesse `http://localhost:8000`, cadastre um usuário inicial (ex.: diretor) e salve a private key + arquivo exportado.
   - Use o CPF/senha no formulário de login; o token fica armazenado no browser (variável JS `authToken`).

3. **Criar contas**
   - Somente o líder aceita `POST /accounts`. A UI envia nome, CPF, email, senha e categoria (`aluno`, `professor`, `diretor`).
   - A resposta já entrega `private_key` e o caminho do arquivo salvo em `data/exports/<account>.json`.

4. **Transferir moedas**
   - Após login, informe `from_account`, `private_key`, `to_account` e `amount`.
   - A operação gera um bloco novo (`GET /blockchain`) e logs CSV em `data/logs/<account>.csv`.

5. **Exportar/Histórico**
   - `GET /accounts/{id}/log` (autenticado com o próprio dono) baixa o CSV da conta.
   - `GET /accounts/{id}/export` (diretor ou dono) devolve JSON com dados públicos.

6. **Replicação/Bootstrap**
   - Seguidores usam `LEADER_URL` para encaminhar transações. Caso iniciem antes do líder, rode `curl -X POST http://localhost:8001/bootstrap`.

## Ring Legacy / Eleição

O arquivo `client_ring.py` continua disponível para rodar nós de eleição. No compose eles sobem no modo headless, conectados em anel e disparando/propagando eleição Bully com relógios de Lamport. A sincronização com o novo ledger ocorre via chamadas HTTP ao líder (rotas `/sync_request` → `/accounts`). Assim mantemos a disciplina original demonstrando procura de nós, envio de criptomoedas e armazenamento em arquivo.

## Testes rápidos

```bash
python -m py_compile client_ring.py atividade.py educoin_project/app/*.py
```

## Próximos passos

- Implementar consenso real (ex.: Raft) para promover automaticamente um seguidor a líder e atualizar o `LEADER_URL` dos demais.
- Adicionar assinatura digital baseada em chave pública das transações/blocos.
- Cobrir toda a API com testes automatizados (pytest + HTTPX AsyncClient) e pipeline CI.
