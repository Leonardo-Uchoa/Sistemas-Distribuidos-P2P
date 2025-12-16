# EduCoin (P2P) — Sistemas Distribuídos

## O que este projeto faz (versão do trabalho)
- **1 nó por máquina** (porta padrão **8000**).
- **Cadastro** de contas (Aluno/Professor/Diretor) com saldo inicial fixo:
  - Aluno: 100
  - Professor: 1000
  - Diretor: 10000
- **Transferência** de EduCoins entre contas usando **chave privada** (não é armazenada).
- **Rede P2P** com:
  - configuração do **meu_url** e conexão a peers **pela interface** (`/dashboard`);
  - **líder** que mantém o estado mais atual e faz broadcast (`/sync`) aos peers.
- **Relógio lógico (Lamport)**:
  - cada mutação de estado incrementa um contador lógico persistido em `state.json`;
  - todas as mensagens levam esse contador para manter causalidade/Lamport entre nós.
- **Reconexão automática de peers**:
  - peers têm *health-check* contínuo e são removidos quando ficam inativos;
  - nós isolados tentam se reconectar periodicamente a peers conhecidos (persistidos em `config.json`).
- **Persistência local** com `state.json`/`config.json`, incluindo membros, transações e peers conhecidos.
- **Cadastro seguro**: cada usuário informa **duas frases diferentes** (uma gera a chave pública e outra gera a chave privada). A chave privada nunca é armazenada, apenas um hash que permite validar transferências.
- **Eleição**:
  - Cada nó recebe um **ID aleatório** ao iniciar.
  - O **líder só muda quando o líder atual cai/desconecta**.
  - Quando isso acontece, o maior **ID** entre os nós ativos vira líder.
  - A eleição percorre os nós em **anel (Ring Election)**: cada nó encaminha a mensagem ao próximo peer conhecido até que o resultado volte ao iniciador, que anuncia o novo líder.

> Observação: isso não é uma blockchain “com consenso real” (PoW/PoS), mas atende ao objetivo didático de
> replicação de estado + coordenação (líder) + tolerância a falhas (eleição).

---

## Como rodar (Docker)
Na raiz do projeto:

```bash
docker compose up --build
```

Acesse:
- Dashboard: http://localhost:8000/dashboard

---

## Como conectar dois computadores (LAN)
### 1) Descubra o IP de cada máquina
```bash
hostname -I
```

### 2) Em cada máquina, abra o dashboard e defina `meu_url`
Ex:
- PC A: `http://10.80.51.76:8000`
- PC B: `http://10.80.60.135:8000`

### 3) Conectar peer
Em um dos dashboards, informe o `peer_url` do outro e clique **Adicionar e Conectar**.

### 4) Firewall (se necessário)
Ubuntu/Zorin:
```bash
sudo ufw allow 8000/tcp
```

---

## Estrutura
- `src/app.py` — servidor Flask + rotas
- `src/funcoes.py` — funções de cripto simples + regras de negócio
- `src/templates/dashboard.html` — interface web

---

## Reset total (quando der estado “bugado”)
```bash
docker compose down -v
docker compose up --build
```

---

## Para desenvolvimento sem Docker
```bash
cd src
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
