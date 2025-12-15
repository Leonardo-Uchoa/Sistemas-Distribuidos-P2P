async function fetchState() {
  const r = await fetch("/api/state");
  return await r.json();
}

async function fetchCluster() {
  const r = await fetch("/api/cluster");
  return await r.json();
}

function escapeHtml(s) {
  return (s ?? "").toString()
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function pad4(n) {
  const x = parseInt(n, 10);
  if (Number.isNaN(x)) return "----";
  return x.toString().padStart(4, "0");
}

function renderUsers(users) {
  const keys = Object.keys(users || {});
  keys.sort((a,b)=> (users[b].saldo||0) - (users[a].saldo||0));
  let html = "<table><thead><tr><th>Tipo</th><th>Nome</th><th>Matrícula</th><th>Saldo</th><th>Chave Pub</th></tr></thead><tbody>";
  for (const pub of keys) {
    const u = users[pub];
    html += "<tr>"
      + "<td>"+escapeHtml(u.tipo)+"</td>"
      + "<td>"+escapeHtml(u.nome)+"</td>"
      + "<td>"+escapeHtml(u.matricula)+"</td>"
      + "<td><b>"+escapeHtml(u.saldo)+"</b></td>"
      + "<td><code>"+escapeHtml(pub.slice(0, 18))+"…</code></td>"
      + "</tr>";
  }
  html += "</tbody></table>";
  return html;
}

function renderTxs(txs) {
  const list = (txs || []).slice().reverse().slice(0, 20);
  let html = "<table><thead><tr><th>Quando</th><th>De</th><th>Para</th><th>Quantia</th><th>TxID</th></tr></thead><tbody>";
  for (const t of list) {
    html += "<tr>"
      + "<td>"+escapeHtml(t.timestamp)+"</td>"
      + "<td><code>"+escapeHtml((t.de_chave_pub||'').slice(0, 12))+"…</code></td>"
      + "<td><code>"+escapeHtml((t.para_chave_pub||'').slice(0, 12))+"…</code></td>"
      + "<td><b>"+escapeHtml(t.quantia)+"</b></td>"
      + "<td><code>"+escapeHtml((t.txid||'').slice(0, 12))+"…</code></td>"
      + "</tr>";
  }
  html += "</tbody></table>";
  return html;
}

function renderMembers(members, leaderUrl, selfUrl) {
  const keys = Object.keys(members || {});
  keys.sort((a,b)=> (members[b].id||0) - (members[a].id||0));
  let html = "<table><thead><tr><th>ID nó</th><th>URL</th><th>Papel</th></tr></thead><tbody>";
  for (const url of keys) {
    const m = members[url] || {};
    const id = pad4(m.id || 0);
    const role =
      (url === leaderUrl) ? "LÍDER" :
      (url === selfUrl) ? "EU" : "peer";
    html += "<tr>"
      + "<td><b>"+escapeHtml(id)+"</b></td>"
      + "<td><code>"+escapeHtml(url)+"</code></td>"
      + "<td>"+escapeHtml(role)+"</td>"
      + "</tr>";
  }
  html += "</tbody></table>";
  return html;
}

async function refresh() {
  const data = await fetchState();
  const state = data.state || {};
  document.querySelector("#usersTable").innerHTML = renderUsers(state.users);
  document.querySelector("#txTable").innerHTML = renderTxs(state.txs);

  // rede
  try {
    const cluster = await fetchCluster();
    document.querySelector("#membersTable").innerHTML =
      renderMembers(cluster.members, cluster.leader_url, cluster.self_url);
  } catch (e) {
    document.querySelector("#membersTable").innerHTML =
      "<div class='muted small' style='padding:10px'>Falha ao carregar membros.</div>";
  }

  document.querySelector("#stateDump").textContent = JSON.stringify(data, null, 2);
}

document.querySelector("#btnRefresh").addEventListener("click", refresh);

document.querySelector("#formRegister").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  const r = await fetch("/register", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  document.querySelector("#registerResult").textContent = JSON.stringify(j, null, 2);
  await refresh();
});

document.querySelector("#formTransfer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  payload.quantia = parseInt(payload.quantia, 10);
  const r = await fetch("/transfer", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  document.querySelector("#transferResult").textContent = JSON.stringify(j, null, 2);
  await refresh();
});

document.querySelector("#formSelfUrl").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  const r = await fetch("/network/set_self_url", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  document.querySelector("#networkResult").textContent = JSON.stringify(j, null, 2);
  await refresh();
});

document.querySelector("#formAddPeer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  const r = await fetch("/network/add_peer", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  document.querySelector("#networkResult").textContent = JSON.stringify(j, null, 2);
  await refresh();
});

// auto
refresh();
