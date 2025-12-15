# EduCoin (protótipo P2P para Sistemas Distribuídos)

Este protótipo foca no essencial do trabalho: **transferir EduCoins entre contas** em uma rede P2P, com:
- **Estado (JSON) replicado** entre nós (via broadcast do líder)
- **Líder automático**: definido por eleição quando o líder atual cai/desconecta
- **Conexão pela interface**: você configura `meu_url` e adiciona `peer_url` sem editar código

## O que já está pronto
- API HTTP (Flask) em cada nó
- Cadastro de conta (Aluno/Professor/Diretor) com saldo inicial (Aluno=100, Prof=1000, Diretor=10000)
- Transferência validada no líder (account-based)
- Broadcast do estado do líder para os peers
- Persistência em `/data/state.json` (volume do Docker)
- Dashboard web em `/dashboard` (inclui painel de rede)

## Como rodar (1 nó por máquina) ✅
```bash
docker compose up --build
```

Acesse:
- http://localhost:8000/dashboard

### Conectar com outro computador (LAN)
No Dashboard, na seção **Rede (P2P)**:
1) Defina **meu_url** como o seu IP/porta acessível pelo seu amigo (ex.: `http://192.168.0.10:8000`)
2) No computador do amigo, faça o mesmo
3) Em um dos nós, adicione o **peer_url** do outro (ex.: `http://192.168.0.11:8000`)

A sincronização e a eleição acontecem automaticamente.

## Rodar 3 nós localmente (apenas para teste) 🧪
```bash
docker compose -f docker-compose.multi.yml up --build
```
Acesse:
- http://localhost:8001/dashboard
- http://localhost:8002/dashboard
- http://localhost:8003/dashboard

## Rotas úteis
- `GET /health` (status do nó e líder)
- `GET /api/state` (estado completo)
- `GET /api/cluster` (membros e líder)
- `POST /network/set_self_url` (configurar meu_url)
- `POST /network/add_peer` (adicionar/conectar peer)
- `POST /register` (criar conta)
- `POST /transfer` (transferir)
