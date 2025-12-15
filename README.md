# Educoin - Sistemas Distribuídos P2P

Este repositório agora contém o protótipo **Educoin**, uma criptomoeda acadêmica pensada para a cadeira de Sistemas Distribuídos. O objetivo principal é permitir que escolas criem contas para estudantes, transfiram moedas pela rede e mantenham o estado sincronizado por meio de um líder.

## O que foi feito

1. **Modelagem do ledger**: criei classes para contas e transações com validações básicas de chave privada e saldo. Os dados ficam persistidos em disco (`LedgerStore`) e podem sobreviver ao restart dos nós.
2. **API FastAPI + UI web**: implementei uma API P2P com FastAPI capaz de criar contas, executar transferências, expor snapshots e replicar o ledger. A mesma aplicação entrega uma interface web simples para visualizar contas/transações e interagir com o sistema.
3. **Sincronização via líder**: nós seguidores encaminham requisições para o líder configurado, enquanto o líder replica o ledger completo para os demais por meio do endpoint `/replicate`, respeitando um token compartilhado.
4. **Stack Docker**: foi adicionada a pasta `educoin_project/` com Dockerfile e `docker-compose.yml` que sobem um líder e dois seguidores automaticamente, cada um com volume próprio para persistência.
5. **Bootstrap/sync**: incluí endpoints utilitários (`/status`, `/sync`, `/bootstrap`) para ajudar em diagnósticos e para seguidores puxarem o ledger completo do líder quando necessário.

## Estrutura principal

```
educoin_project/
  app/
    ledger.py        # regras de contas/transações
    storage.py       # persistência em JSON thread-safe
    p2p.py           # broadcast e proxy para o líder
    main.py          # FastAPI + UI
    templates/index.html
  requirements.txt
  Dockerfile
```

## Como executar via Docker Compose

1. **Build e subida da stack**
   ```bash
   docker compose up --build
   ```
   Isso cria 3 serviços: `educoin-leader` (porta 8000), `educoin-node-1` (porta 8001) e `educoin-node-2` (porta 8002). Cada nó tem um volume em `./data/*` para persistir seu ledger.

2. **Acessar a interface**
   Abra `http://localhost:8000` para o líder (interface completa) ou `http://localhost:8001` / `:8002` para visualizar os seguidores. Todos expõem a mesma UI.

3. **Criar conta**
   - Use o formulário "Criar conta" na UI ou via API (`POST /accounts` com `{ "name": "Fulano" }`).
   - O líder retorna o `private_key`. Salve-o, pois essa informação não é mostrada novamente.

4. **Transferir educoins**
   - No formulário "Transferir Educoins" informe `from_account`, `private_key`, `to_account` e `amount`.
   - A API valida saldo e chave privada antes de registrar a transação.

5. **Sincronização manual (opcional)**
   - Em seguidores: `curl -X POST http://localhost:8001/bootstrap` para puxar um snapshot completo caso tenham iniciado antes do líder.

## Endpoints importantes

- `GET /` – interface web.
- `GET /status` – mostra metadados do nó (id, se é líder, peers, contagens).
- `GET /accounts` – snapshot completo de contas e transações.
- `POST /accounts` – cria conta (seguidores encaminham para o líder automaticamente).
- `POST /transactions` – transfere educoins.
- `POST /replicate` – usado pelo líder para enviar snapshot aos peers (proteção por header `x-leader-token`).
- `POST /bootstrap` – seguidores puxam snapshot inicial do líder.

## Próximos passos sugeridos

- Implementar autenticação adequada (ex: assinaturas digitais) e histórico imutável baseado em blockchain real.
- Adicionar consenso/election automatizada (Raft ou Bully) para troca de liderança em runtime.
- Criar testes automatizados que cubram transferências concorrentes e validação de replicação.

## Legacy

Os arquivos originais (`client_ring.py`, `atividade.py`) foram mantidos para referência do antigo protótipo de mural, mas o fluxo principal da Educoin está concentrado em `educoin_project/`.
