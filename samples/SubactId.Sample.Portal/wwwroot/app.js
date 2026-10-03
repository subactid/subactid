// The portal page. It holds no credentials. It calls only the portal server, which holds the
// human's token. Only the agent holds task tokens.

const $ = (id) => document.getElementById(id);

const state = {
  session: null,
  profiles: {},
  tools: {},
  taskId: null,
  task: null,
  kind: 'short',
  polling: null,
  ledgerTick: 0,
};

async function api(path, options) {
  const response = await fetch(path, {
    ...options,
    headers: options?.body ? { 'Content-Type': 'application/json' } : undefined,
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  return { ok: response.ok, status: response.status, body };
}

function fail(message) {
  const box = $('error');
  box.textContent = message;
  box.hidden = !message;
}

// ---- sign in ----------------------------------------------------------------

$('signIn').addEventListener('click', () => { window.location.href = '/login'; });

// Clicking a demo account fills in the sign-in form.
for (const chip of document.querySelectorAll('.account[data-as]')) {
  chip.addEventListener('click', () => {
    $('username').value = chip.dataset.as;
    $('password').value = chip.dataset.as;
    $('passwordForm').requestSubmit();
  });
}

$('passwordForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  fail('');
  const { ok, body } = await api('/login', {
    method: 'POST',
    body: JSON.stringify({ username: $('username').value, password: $('password').value }),
  });
  if (!ok) {
    fail(body.error_description || 'Sign-in failed.');
    return;
  }
  window.location.href = '/';
});

$('signOut').addEventListener('click', async () => {
  await api('/logout', { method: 'POST' });
  window.location.href = '/';
});

async function load() {
  const url = new URL(window.location.href);
  if (url.searchParams.has('error')) {
    fail(`Sign-in did not finish: ${url.searchParams.get('error')}`);
    window.history.replaceState({}, '', '/');
  }

  const mode = await api('/api/login-mode');
  const password = (mode.body.mode || 'password') === 'password';
  $('passwordForm').hidden = !password;
  $('signIn').hidden = password;
  for (const chip of document.querySelectorAll('.account[data-as]')) {
    chip.disabled = !password;
  }

  const { body } = await api('/api/session');
  state.session = body;

  $('signedOut').hidden = body.authenticated;
  $('signedIn').hidden = !body.authenticated;
  $('who').hidden = !body.authenticated;
  if (!body.authenticated) return;

  $('whoName').textContent = body.username;
  renderHuman(body);

  const [profiles, tools] = await Promise.all([api('/api/profiles'), api('/api/tools')]);
  state.profiles = profiles.body || {};
  state.tools = (tools.body && tools.body.tools) || {};
  renderKinds();
  renderTools();
  refreshLedger();
}

// ---- the human's token ------------------------------------------------------

function renderHuman(session) {
  const c = session.claims;
  const roles = c.realm_roles && c.realm_roles.length ? c.realm_roles.join(' ') : '(none)';
  $('humanClaims').innerHTML = [
    row('iss', escape(c.iss)),
    row('sub', `<span class="match">${escape(c.sub)}</span>`),
    row('aud', escape(c.aud)),
    row('roles', escape(roles)),
    row('scope', chips(session.scopes, session.scopes)),
  ].join('');

  const note = session.scopes.includes('jira:comment')
    ? 'This human holds jira-commenter, so the identity provider put jira:comment in their token.'
    : 'This human holds no jira-commenter role, so jira:comment is not in their token however loudly anything asks for it.';
  $('startNote').textContent = note;
}

function row(name, value) {
  return `<div><dt>${name}</dt><dd>${value}</dd></div>`;
}

function chips(granted, requested) {
  const all = [...new Set([...(requested || []), ...(granted || [])])];
  if (!all.length) return '<span class="scope gone">(none)</span>';
  return `<span class="scopes">${all.map((s) =>
    `<span class="scope${granted.includes(s) ? '' : ' gone'}">${escape(s)}</span>`).join('')}</span>`;
}

function escape(value) {
  return String(value ?? '').replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
}

// ---- starting a task --------------------------------------------------------

function renderKinds() {
  $('kinds').innerHTML = Object.entries(state.profiles).map(([kind, p]) => `
    <label class="choice">
      <input type="radio" name="kind" value="${escape(kind)}" ${kind === state.kind ? 'checked' : ''}>
      ${escape(kind)} <small>task ${short(p.max_task_ttl)}, token ${short(p.max_token_ttl)}</small>
    </label>`).join('');
  for (const input of document.querySelectorAll('input[name=kind]')) {
    input.addEventListener('change', () => { state.kind = input.value; });
  }
}

function short(iso) {
  return String(iso || '').replace('PT', '').toLowerCase();
}

function renderTools() {
  $('toolButtons').innerHTML = Object.entries(state.tools).map(([name, t]) =>
    `<button data-tool="${escape(name)}" title="needs ${escape(t.scope)}${t.high_risk ? ', introspected on every call' : ''}">${escape(name)}</button>`).join(' ');
  for (const button of document.querySelectorAll('#toolButtons button')) {
    button.addEventListener('click', () => callTool(button.dataset.tool, 'task'));
  }
}

$('start').addEventListener('click', async () => {
  fail('');
  const scope = [...document.querySelectorAll('input[name=scope]:checked')].map((i) => i.value).join(' ');
  $('start').disabled = true;
  const { ok, body } = await api('/api/tasks', { method: 'POST', body: JSON.stringify({ kind: state.kind, scope }) });
  $('start').disabled = false;

  if (!ok) {
    fail(`${body.error || 'refused'}: ${body.error_description || 'The control plane would not start the task.'}`);
    return;
  }

  state.taskId = body.task_id;
  adopt(body);
  startPolling();
});

// ---- a live task ------------------------------------------------------------

function startPolling() {
  clearInterval(state.polling);
  state.polling = setInterval(poll, 1000);
}

async function poll() {
  if (!state.taskId) return;
  const { ok, body } = await api(`/api/tasks/${encodeURIComponent(state.taskId)}`);
  if (ok) adopt(body);
  if (++state.ledgerTick % 4 === 0) refreshLedger();
}

function adopt(task) {
  state.task = task;
  $('taskSection').hidden = false;
  $('logSection').hidden = false;
  renderTask(task);
  renderLog(task);
}

function renderTask(task) {
  const c = task.token_claims;
  const same = c.sub === state.session.claims.sub;
  const granted = task.scope ? task.scope.split(' ') : [];
  const requested = task.requested_scope ? task.requested_scope.split(' ') : [];

  const panel = $('agentToken');
  panel.classList.remove('empty');
  panel.innerHTML = `
    <h3>The agent's task token</h3>
    <p class="sub">Issued by the control plane. This is the only thing the agent can act with.</p>
    <dl class="claims">
      ${row('iss', escape(c.iss))}
      ${row('sub', `<span class="${same ? 'match' : ''}">${escape(c.sub)}</span>${same ? ' &larr; you, not the agent' : ''}`)}
      ${row('act', `<span class="actor">${escape(c.act)}</span> &larr; the agent, as the actor`)}
      ${row('aud', escape(c.aud))}
      ${row('scope', chips(granted, requested))}
      ${row('task', escape(task.task_id))}
    </dl>
    <div class="meters">
      <div class="meter">
        <span class="label">token expires in</span>
        <span class="value ${task.token_expires_in <= 10 ? 'warn' : ''}">${task.running ? task.token_expires_in + 's' : '—'}</span>
        <div class="bar"><i style="width:${task.running ? Math.min(100, task.token_expires_in / 30 * 100) : 0}%"></i></div>
      </div>
      <div class="meter">
        <span class="label">task ends in</span>
        <span class="value">${task.running ? clock(task.task_expires_in) : '—'}</span>
        <div class="bar task"><i style="width:${task.running ? Math.min(100, task.task_expires_in / totalTaskSeconds(task) * 100) : 0}%"></i></div>
      </div>
      <div class="meter">
        <span class="label">renewals</span>
        <span class="value">${task.refreshes}</span>
      </div>
    </div>`;

  const banner = $('taskBanner');
  if (task.running) {
    banner.hidden = true;
  } else {
    banner.hidden = false;
    banner.className = 'banner ended';
    banner.textContent = endedText(task.ended_reason);
  }

  for (const id of ['renew', 'narrow', 'revoke', 'tryHuman']) {
    $(id).disabled = !task.running;
  }
  for (const button of document.querySelectorAll('#toolButtons button')) {
    button.disabled = !task.running;
  }
}

function endedText(reason) {
  if (reason === 'operator_kill_switch') {
    return 'Revoked. The token it was holding is still unexpired and still correctly signed — and a high-risk tool finds out it is dead on the very next call.';
  }
  if (reason === 'task_expired') {
    return 'The task reached its max_task_ttl and ended. Nothing under it can be renewed: a token never outlives its task.';
  }
  return `The task ended: ${reason}.`;
}

function totalTaskSeconds(task) {
  const profile = state.profiles[task.kind];
  const minutes = profile ? parseInt(String(profile.max_task_ttl).replace(/\D/g, ''), 10) : 10;
  return Math.max(1, minutes * 60);
}

function clock(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${String(s).padStart(2, '0')}s` : `${s}s`;
}

function renderLog(task) {
  const log = $('log');
  if (!task.events.length) {
    log.innerHTML = '<div class="empty">Nothing yet.</div>';
    return;
  }

  const pinned = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
  log.innerHTML = task.events.map((e) => `
    <div class="line">
      <span class="at">${new Date(e.at).toLocaleTimeString()}</span>
      <span class="tag ${e.level}">${e.level}</span>
      <span class="body">${escape(e.message)}${e.detail ? `<div class="detail">${escape(e.detail)}</div>` : ''}</span>
    </div>`).join('');
  if (pinned) log.scrollTop = log.scrollHeight;
}

// ---- acting -----------------------------------------------------------------

async function callTool(tool, credential) {
  if (!state.taskId) return;
  const { body } = await api(`/api/tasks/${encodeURIComponent(state.taskId)}/call`, {
    method: 'POST',
    body: JSON.stringify({ tool, credential }),
  });
  if (body.task) adopt(body.task);
  refreshLedger();
}

$('tryHuman').addEventListener('click', () => {
  const tool = Object.keys(state.tools)[0] || 'search';
  callTool(tool, 'human');
});

$('renew').addEventListener('click', async () => {
  const { body } = await api(`/api/tasks/${encodeURIComponent(state.taskId)}/refresh`, { method: 'POST' });
  if (body.task_id) adopt(body);
  refreshLedger();
});

$('narrow').addEventListener('click', async () => {
  const { body } = await api(`/api/tasks/${encodeURIComponent(state.taskId)}/narrow`, {
    method: 'POST',
    body: JSON.stringify({ scope: 'jira:read' }),
  });
  if (body.task_id) adopt(body);
  refreshLedger();
});

$('revoke').addEventListener('click', async () => {
  const { body } = await api(`/api/tasks/${encodeURIComponent(state.taskId)}/revoke`, { method: 'POST' });
  if (body.task_id) adopt(body);
  refreshLedger();
});

// ---- the ledger -------------------------------------------------------------

async function refreshLedger() {
  const { ok, body } = await api('/api/audit');
  if (!ok || !body.records) return;
  $('ledger').innerHTML = body.records.map((r) => `
    <tr>
      <td>${r.seq}</td>
      <td>${escape(r.event)}</td>
      <td class="${r.decision || ''}">${escape(r.decision || '—')}</td>
      <td>${escape(r.reason || '—')}</td>
      <td>${escape(r.agent_id || '—')}</td>
      <td>${escape(r.scope || '—')}</td>
    </tr>`).join('');
}

load();
