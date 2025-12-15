# Documentação Final do Projeto Educoin

## Visão Geral

O objetivo do Educoin é demonstrar um sistema de criptomoeda educacional com distribuição peer-to-peer, incluindo eleição de líder, propagação de transações pelo anel e persistência segura de contas/chaves. O projeto foi desenhado em duas camadas:

1. **Ledger FastAPI** (pasta `educoin_project/`): cuida das contas, autenticação, blockchain e exportação de dados.
2. **Anel de eleição** (`client_ring.py`): mantém relógio de Lamport, algoritmo Bully e dissemina tanto eleições quanto transações.

A stack Docker levanta múltiplos contêineres desses componentes para simular uma rede completa.

## Decisões de Arquitetura

- **Persistência**: cada nó grava `ledger.json`, logs CSV e exports JSON sob `./data/<node>/`. O `LedgerStore` usa escrita atômica para evitar corrupção.
- **Contas/Chaves**: ao criar uma conta o backend gera chave pública/privada usando `secrets.token_hex`, salva apenas o hash da chave privada e exporta um arquivo JSON para o usuário guardar.
- **Blockchain**: cada transferência vira um bloco com hash `SHA-256` encadeando `previous_hash`. Isso garante um histórico auditável mesmo sem consenso completo.
- **Autenticação**: `/login` entrega um token bear (guardado em memória) que permite acessar `/transactions`, `/accounts/{id}/log`, etc. O token também é reutilizado pelos ring nodes para retransmitir a transação.
- **Propagação pelo anel**: seguidores não chamam o líder diretamente; enviam `txn_event` para seu ring node local, que percorre o anel até o líder atual. Isso demonstra o conceito de “disparar, participar, propagar” do quadro da disciplina.
- **Eleição dinâmica**: quando o algoritmo Bully reconhece um líder, os ring nodes chamam `POST /election/leader` em cada backend com `x-ring-token`. O `LeaderState` atualiza o papel local sem reiniciar o serviço.

## Comandos Utilizados (principais)

- **Build e subida**:
  ```bash
  docker compose up --build
  ```
- **Verificar logs de um serviço**:
  ```bash
  docker compose logs educoin-leader
  docker compose logs ring-node-a
  ```
- **Executar testes automatizados**:
  ```bash
  python -m venv .venv
  source .venv/bin/activate
  pip install -r requirements-dev.txt
  pytest -q
  ```
- **Formatter básico / lint**: apenas `python -m py_compile ...` para verificar sintaxe.

## Fluxo Completo da Eleição

1. Cada `ring-node-*` conhece o próximo nó (`NEXT_NODE`) formando o anel.
2. Ao iniciar todos enviam `GET /iniciaeleicao` ou disparam automaticamente quando não conhecem um líder.
3. O algoritmo Bully compara `NODE_ID` e propaga `POST /eleicao` até que o maior ID se reconheça líder.
4. O vencedor envia `POST /eleito` ao próximo nó; a mensagem percorre o anel informando quem venceu.
5. Quando um ring node recebe `/eleito`, chama `notify_ledgers_of_election`, que monta um payload `{"leader_id": <ledger_id>, "leader_url": <url>}` e faz `POST /election/leader` em todos os backends (header `x-ring-token=ring-secret`).
6. Cada backend atualiza `LeaderState`; o líder passa a executar `PeerSync` e aceitar operações que exigem liderança.
7. Logs do processo podem ser observados em `docker compose logs ring-node-a` ou consultando `GET /status` nos backends para ver `leader_id` atual.

## Como Verificar os Ring Nodes

- **Status**: `curl http://localhost:8101/leader` mostra o líder conhecido pelo nó A.
- **Mural**: `curl http://localhost:8101/mural` retorna mensagens/eventos registrados.
- **Eleições**: `curl http://localhost:8101/iniciaeleicao` força uma nova eleição.
- **Logs**: `docker compose logs ring-node-b` permite acompanhar `vc_increment`, propagação de `txn_event` e anúncios de líder.

## Como um Seguidor Se Torna Líder Quando o Atual Cai

1. Derrube o contêiner líder (`docker compose stop educoin-leader`).
2. Um ring node perceberá a ausência (timeout) e iniciará nova eleição (etapas descritas acima).
3. Supondo que `ring-node-b` (ID 102) vença, ele enviará `/eleito` → `notify_ledgers_of_election` com `leader_id=node-1`, `leader_url=http://educoin-node-1:8000`.
4. O backend `educoin-node-1` recebe `POST /election/leader`, atualiza `LeaderState` e, em log, passa a reportar `is_leader=true` e iniciar `PeerSync`.
5. Os demais seguidores atualizam automaticamente o `leader_url` interno e passam a encaminhar transações pelo anel até atingir o novo líder.
6. Pode-se validar com `curl http://localhost:8001/status` (agora deverá exibir `is_leader: true`).

## Exemplos de Uso da API

### Criar Conta (somente líder)
```bash
curl -X POST http://localhost:8000/accounts \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "Maria",
        "cpf": "12345678901",
        "email": "maria@escola.edu",
        "password": "senha123",
        "category": "aluno"
      }'
```
Resposta inclui `account.id`, `public_key` e `private_key` (salve!).

### Login
```bash
curl -X POST http://localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"cpf":"12345678901", "password":"senha123"}'
```
Retorna `{ "token": "...", "account": {...} }`.

### Transferência via seguidor (propagada pelo anel)
```bash
TOKEN="<resultado do login>"
curl -X POST http://localhost:8001/transactions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
        "from_account": "<id_origem>",
        "to_account": "<id_destino>",
        "private_key": "<chave_privada>",
        "amount": 10
      }'
```
O seguidor enviará um `txn_event` para o anel; quando o líder aplicar a transferência o JSON retornará com `transaction.id`.

### Download do Log da Conta
```bash
curl -L -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/accounts/<id_origem>/log -o log.csv
```

### Consultar Blockchain
```bash
curl http://localhost:8000/blockchain
```

## Passo a Passo dos Testes Automatizados

1. Crie um ambiente virtual e instale dependências de desenvolvimento:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   ```
2. Execute os testes:
   ```bash
   pytest -q
   ```
   O teste `tests/test_flow.py` recria o app em memória, cadastra usuários, realiza login, ajusta saldo, executa transferência e valida o log.
3. Para simular o ambiente real, suba o Docker (`docker compose up`) e utilize os comandos `curl` descritos anteriormente; isso funciona como um roteiro manual para demonstração.

---
Esta documentação complementa o README principal com decisões, comandos e procedimentos detalhados, permitindo que qualquer membro da equipe replique o ambiente, entenda o raciocínio por trás das escolhas e execute testes ponta a ponta.
