# Educoin - Rede P2P Acadêmica

Este repositório contém o protótipo **Educoin**, uma criptomoeda de uso escolar construída sobre conceitos de Sistemas Distribuídos. Após esta iteração o sistema oferece:

- **Gestão completa de usuários/contas** com campos obrigatórios (nome, CPF, e-mail, categoria) e autenticação por senha.
- **Geração e armazenamento formal de chaves**: cada cadastro cria automaticamente chave pública/privada e gera um arquivo JSON exportável (pasta `data/exports`).
- **Ledger persistente + blockchain**: toda transferência gera um bloco com hash encadeado, guardado em `data/ledger.json`. Logs individuais por conta são gravados em CSV (pasta `data/logs`).
- **Interface web com login** para criar contas (somente líder), transferir moedas autenticado, baixar log/export e visualizar a blockchain.
- **API FastAPI** com endpoints de autenticação, transações, blockchain, replicação e anúncio de liderança (`/election/leader`). Seguidores encaminham operações ao líder automaticamente (agora utilizando o anel para propagar transações).
- **Stack Docker Compose** que sobe líder + 2 seguidores + 3 nós do anel Bully/Lamport. Os ring nodes notificam o backend sempre que elegem um novo líder, promovendo a liderança dinamicamente.

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
   - Se você estiver conectado a um seguidor (porta 8001/8002), o pedido é enviado ao anel via `/txn_event`, circula pelos `ring-node-*` até chegar ao ring leader, que por sua vez aciona o backend eleito. Isso demonstra o fluxo “disparar → participar → propagar”.
   - A operação gera um bloco novo (`GET /blockchain`) e logs CSV em `data/logs/<account>.csv`.

5. **Exportar/Histórico**
   - `GET /accounts/{id}/log` (autenticado com o próprio dono) baixa o CSV da conta.
   - `GET /accounts/{id}/export` (diretor ou dono) devolve JSON com dados públicos.

6. **Replicação/Bootstrap**
   - Seguidores usam o endereço de líder fornecido via `/election/leader`. Se iniciem antes de receber o anúncio, rode `curl -X POST http://localhost:8001/bootstrap`.

## Eleição dinâmica integrada

- Os contêineres `ring-node-a/b/c` executam `client_ring.py` sem GUI. Cada nó possui um `RING_NODE_ID` (101–103) e conhece a tabela `LEDGER_MAP` mapeando ID do anel → `NODE_ID`/URL do backend.
- Quando o algoritmo Bully conclui uma eleição (`/eleito`), os ring nodes chamam `POST /election/leader` em todos os serviços FastAPI com header `x-ring-token` (`ring-secret` por padrão). O corpo contém `{"leader_id": "...", "leader_url": "http://..."}`.
- Além disso, todo `POST /transactions` feito em seguidores é encapsulado como `txn_event` e propagado pelos ring nodes até alcançar o líder corrente; somente quando a mensagem chega ao nó que está com a liderança é que o backend processa a transferência. Assim o anel participa ativamente da propagação de transações e pode ser observado pelos logs (`docker compose logs ring-node-a`).
- O backend atualiza o papel imediatamente: se o `leader_id` recebido corresponder ao `NODE_ID` local, ele assume o papel de líder, liga o `PeerSync` e passa a aceitar criação de contas/transferências. Os demais passam a encaminhar para o novo `leader_url`.
- Você pode verificar o estado atual acessando `GET /status` em cada nó ou consultando os logs dos ring nodes (`docker compose logs ring-node-a`).

## Ring Legacy / Eleição

O arquivo `client_ring.py` continua disponível como serviço autônomo ou dentro do compose. Ele mantém o mural/Vetor de Lamport para fins didáticos e, agora, também notifica o backend do Educoin quando elege um líder. Isso preserva os conceitos originais (disparar/participar/propagar, guardar chaves em arquivo, relógio lógico) e integra com o ledger que executa as transferências.

## Testes rápidos

```bash
python -m py_compile client_ring.py atividade.py educoin_project/app/*.py
```

## Testes automatizados / roteiro

Há um teste end-to-end (`tests/test_flow.py`) que usa `fastapi.testclient` para simular o fluxo completo: criar contas, autenticar, ajustar saldo, transferir e baixar o log. Para executá-lo:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

Isso configura um ledger isolado em diretório temporário e serve como roteiro reproduzindo os principais endpoints sem precisar subir o Docker.

## Próximos passos

- Implementar consenso real (ex.: Raft) para promover automaticamente um seguidor a líder e atualizar o `LEADER_URL` dos demais.
- Adicionar assinatura digital baseada em chave pública das transações/blocos.
- Cobrir toda a API com testes automatizados (pytest + HTTPX AsyncClient) e pipeline CI.
