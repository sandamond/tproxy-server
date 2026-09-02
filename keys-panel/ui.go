package main

const pageTemplates = `
{{define "login"}}<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>tproxy-keys</title><link rel="stylesheet" href="/panel.css">
</head><body class="login-body">
<form class="login" method="post" action="/login">
  <h1>tproxy-keys</h1>
  <p class="muted">Токен лежит на сервере в <code>/etc/tproxy-keys/panel.token</code></p>
  {{if .Error}}<p class="flash bad">{{.Error}}</p>{{end}}
  <input type="password" name="token" placeholder="Токен доступа" autocomplete="off" autofocus>
  <button type="submit">Войти</button>
</form>
</body></html>{{end}}

{{define "index"}}<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>tproxy-keys</title><link rel="stylesheet" href="/panel.css">
</head><body>
<header>
  <div class="bar">
    <div class="title">tproxy-keys <span class="host">{{.Hostname}}</span></div>
    <form method="post" action="/logout"><button class="link-button" type="submit">Выйти</button></form>
  </div>
  <div class="chips">
    <span class="chip {{if eq .Ready "ready"}}ok{{else}}bad{{end}}">relay: {{.Ready}}</span>
    {{range .Units}}<span class="chip {{if eq .State "active"}}ok{{else}}bad{{end}}">{{.Name}}: {{.State}}</span>{{end}}
  </div>
</header>

<main>
{{if .Flash}}<p class="flash {{if .FlashOK}}good{{else}}bad{{end}}">{{.Flash}}</p>{{end}}
{{if .Error}}<p class="flash bad">{{.Error}}</p>{{end}}

<p class="warn">Любое изменение ключей перезапускает релей и MTProxy: активные сессии
оборвутся, клиенты переподключатся сами через несколько секунд.</p>

<h2>Ключи</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Имя</th><th>Метка</th><th>Режим</th><th>Секрет</th><th>Создан</th><th></th></tr></thead>
  <tbody>
  {{range .Keys}}
    <tr>
      <td class="mono nowrap">{{.Profile.Name}}</td>
      <td>{{if .Meta.Label}}{{.Meta.Label}}{{else}}—{{end}}</td>
      <td class="mono dim">{{if .Profile.CarrierMode}}{{.Profile.CarrierMode}}{{else}}https{{end}}</td>
      <td class="mono nowrap">
        <span class="secret" data-full="{{.Profile.Secret}}" data-shown="0">••••••••••••••••</span>
        <button class="mini reveal" type="button">показать</button>
        <button class="mini copy" type="button" data-copy="{{.Profile.Secret}}">секрет</button>
        <button class="mini copy" type="button" data-copy="{{.Link}}">ссылка</button>
      </td>
      <td class="dim nowrap">{{if .CreatedShort}}{{.CreatedShort}}{{else}}—{{end}}</td>
      <td class="actions">
        <form method="post" action="/keys/rotate" class="applying" data-confirm="Перевыпустить ключ {{.Profile.Name}}? Старая ссылка перестанет работать.">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <input type="hidden" name="name" value="{{.Profile.Name}}">
          <button class="mini" type="submit">перевыпустить</button>
        </form>
        <form method="post" action="/keys/revoke" class="applying" data-confirm="Отозвать ключ {{.Profile.Name}}? Доступ пропадёт сразу.">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <input type="hidden" name="name" value="{{.Profile.Name}}">
          <button class="mini danger" type="submit">отозвать</button>
        </form>
      </td>
    </tr>
  {{end}}
  </tbody>
</table>
</div>

<h2>Новый ключ</h2>
<form class="add applying" method="post" action="/keys/add" data-confirm="Создать ключ? Релей перезапустится.">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input name="name" placeholder="имя (латиница, цифры, . _ -)" required>
  <input name="label" placeholder="метка, например «телефон мамы»">
  <select name="mode">
    <option value="">https (по умолчанию)</option>
    <option value="https-lanes">https-lanes</option>
    <option value="websocket">websocket</option>
    <option value="websocket-lanes">websocket-lanes</option>
  </select>
  <button type="submit">Создать</button>
</form>

<p class="muted small">Ссылка для клиента: <span class="mono">https://t.me/webproxy?server={{.Hostname}}&amp;secret=…</span>
— или те же хост и секрет, введённые в клиенте вручную.</p>
</main>
<script src="/panel.js"></script>
</body></html>{{end}}
`

const panelCSS = `
:root {
  --bg:#0e1116; --card:#171d26; --line:#252d3a; --text:#d9e0ea; --muted:#8a97a8;
  --ok:#5ac8a8; --bad:#e0685f; --warn:#d9a441;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
code,.mono{font-family:var(--mono);font-size:13px}
.dim{color:var(--muted)}
.muted{color:var(--muted)}
.small{font-size:13px}
header{border-bottom:1px solid var(--line);background:#151a22;padding:14px 24px}
.bar{display:flex;justify-content:space-between;align-items:center;gap:16px}
.title{font-weight:600}
.host{color:var(--muted);font-family:var(--mono);font-size:13px;font-weight:400;margin-left:8px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.chip{font-family:var(--mono);font-size:12px;border:1px solid var(--line);
  border-radius:999px;padding:3px 10px;color:var(--muted)}
.chip.ok{color:var(--ok);border-color:#2f7a66}
.chip.bad{color:var(--bad);border-color:#7a3f3a}
main{max-width:1080px;margin:0 auto;padding:28px 24px 64px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);
  font-weight:500;margin:32px 0 14px}
.warn{border:1px solid var(--line);border-left:3px solid var(--warn);background:#151a22;
  border-radius:8px;padding:12px 16px;color:var(--muted);font-size:14px}
.flash{border-radius:8px;padding:12px 16px;font-size:14px;border:1px solid var(--line)}
.flash.good{border-left:3px solid var(--ok);background:#14201c}
.flash.bad{border-left:3px solid var(--bad);background:#221618;color:#f0c7c3}
/* a revealed secret may outgrow the viewport; scroll the table, never the page */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);font-weight:500}
.actions{white-space:nowrap}
.nowrap{white-space:nowrap}
.actions form{display:inline}
button{font:inherit;cursor:pointer;border-radius:7px;border:1px solid var(--line);
  background:#202834;color:var(--text);padding:8px 16px}
button:hover{border-color:#3a475a}
button[disabled]{opacity:.5;cursor:progress}
.mini{font-size:12px;padding:3px 7px;margin-left:3px}
.mini.danger{color:#f0a9a3;border-color:#5d3733}
.link-button{background:none;border:none;color:var(--muted);padding:4px 0}
.link-button:hover{color:var(--text)}
/* the masked placeholder stays compact so the action buttons are always in
   view; revealing widens the row and the wrapper scrolls it */
.secret{display:inline-block;min-width:140px;letter-spacing:.08em}
form.add{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,select{font:inherit;background:#12171f;color:var(--text);border:1px solid var(--line);
  border-radius:7px;padding:8px 12px}
input{min-width:230px}
input::placeholder{color:#5f6b7c}
.login-body{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login{background:var(--card);border:1px solid var(--line);border-radius:12px;
  padding:32px;width:360px;display:flex;flex-direction:column;gap:14px}
.login h1{font-size:19px;margin:0}
.login input{min-width:0;width:100%}
.login button{width:100%}
@media(max-width:720px){
  .nowrap{white-space:normal}
  .table-wrap{overflow-x:visible}
  table,thead,tbody,tr,td,th{display:block}
  thead{display:none}
  tr{border:1px solid var(--line);border-radius:8px;margin-bottom:12px;padding:6px 4px}
  td{border:none;padding:6px 12px}
  input{min-width:0;width:100%}
  form.add{flex-direction:column;align-items:stretch}
}
`

const panelJS = `
document.addEventListener('click', function (event) {
  var target = event.target;

  if (target.classList.contains('reveal')) {
    var cell = target.parentElement.querySelector('.secret');
    if (cell.dataset.shown === '1') {
      cell.textContent = '••••••••••••••••';
      cell.dataset.shown = '0';
      target.textContent = 'показать';
    } else {
      cell.textContent = cell.dataset.full;
      cell.dataset.shown = '1';
      target.textContent = 'скрыть';
    }
    return;
  }

  if (target.classList.contains('copy')) {
    var value = target.dataset.copy;
    var done = function () {
      var original = target.textContent;
      target.textContent = 'скопировано';
      setTimeout(function () { target.textContent = original; }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done, function () { fallbackCopy(value, done); });
    } else {
      fallbackCopy(value, done);
    }
  }
});

function fallbackCopy(value, done) {
  var area = document.createElement('textarea');
  area.value = value;
  area.setAttribute('readonly', '');
  document.body.appendChild(area);
  area.select();
  try { document.execCommand('copy'); done(); } catch (error) { window.prompt('Скопируйте вручную:', value); }
  document.body.removeChild(area);
}

// Every mutating form restarts two services, so confirm first and then make the
// wait visible instead of leaving a dead-looking page.
document.querySelectorAll('form.applying').forEach(function (form) {
  form.addEventListener('submit', function (event) {
    var question = form.dataset.confirm;
    if (question && !window.confirm(question)) {
      event.preventDefault();
      return;
    }
    form.querySelectorAll('button').forEach(function (button) {
      button.disabled = true;
      button.textContent = 'применяется…';
    });
  });
});
`
