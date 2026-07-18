// Nemesis Forge — shared front-end: nav, auth gate, and small helpers.
const RUNGS = ["UNVERIFIED","PROVEN_FAULT","PROVEN_REACHABLE","PROVEN_SECURITY",
               "PROVEN_PRIMITIVE","PROVEN_EXPLOIT","VENDOR_READY"];

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>(
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function fmtTime(ts){ if(!ts) return '—'; const d=new Date(ts*1000);
  return d.toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
function clock(ts){ if(!ts) return ''; return new Date(ts*1000).toLocaleTimeString([], {hour12:false}); }
function ago(ts){ if(!ts) return ''; const s=Math.max(0,Date.now()/1000-ts);
  if(s<60) return Math.round(s)+'s'; if(s<3600) return Math.round(s/60)+'m';
  if(s<86400) return Math.round(s/3600)+'h'; return Math.round(s/86400)+'d'; }
function statusClass(s){ return 'st-'+(s||'idle'); }
function pill(s,label){ return `<span class="pill ${statusClass(s)}"><span class="d" style="background:currentColor"></span>${esc(label||s||'—')}</span>`; }

function navHTML(active){
  const tab=(id,href,label)=>`<a class="tab ${active===id?'on':''}" href="${href}"${active===id?'':' target="_self"'}>${label}</a>`;
  return `<nav class="nav">
    <a class="brand" href="/"><span class="mark">NF</span>NEMESIS <b>FORGE</b></a>
    ${tab('console','/','Console')}
    ${tab('activity','/activity','Live Activity')}
    ${tab('history','/history','History')}
    ${tab('health','/health','Health')}
    <span class="sp"></span>
    <span class="who" id="whoami"></span>
    <span class="dot" id="healthDot" title="system health"></span>
    <button class="btn" id="signout" style="margin-left:12px;display:none" onclick="signout()">Sign out</button>
  </nav>`;
}

function loginHTML(){
  return `<div id="loginOverlay" style="display:none;position:fixed;inset:0;background:#0b0e13ee;z-index:200;align-items:center;justify-content:center">
    <form onsubmit="return doLogin(event)" class="card" style="width:330px;padding:26px 28px">
      <div style="font:700 17px system-ui;letter-spacing:.5px">NEMESIS <b style="color:var(--accent2)">FORGE</b></div>
      <div class="mut" style="font-size:12px;margin:4px 0 16px">operator sign-in</div>
      <label class="fld">Username</label>
      <input id="lgUser" autocomplete="username" style="width:100%;margin-bottom:11px" />
      <label class="fld">Password</label>
      <input id="lgPass" type="password" autocomplete="current-password" style="width:100%" />
      <div id="lgErr" style="color:var(--bad);font-size:12px;min-height:16px;margin:9px 0"></div>
      <button class="btn primary" style="width:100%" type="submit">Sign in</button>
    </form></div>`;
}

async function mount(active){
  document.body.insertAdjacentHTML('afterbegin', navHTML(active)+loginHTML());
  const r = await fetch('/api/me');
  if(r.status===401){ document.getElementById('loginOverlay').style.display='flex';
    document.getElementById('lgUser').focus(); return false; }
  const me = await r.json();
  if(me.auth){ document.getElementById('whoami').textContent=me.user;
    document.getElementById('signout').style.display=''; }
  pollHealthDot();
  return true;
}
async function doLogin(e){ e.preventDefault();
  const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({username:lgUser.value,password:lgPass.value})});
  if(r.ok) location.reload(); else document.getElementById('lgErr').textContent='Invalid credentials';
  return false; }
async function signout(){ await fetch('/api/logout',{method:'POST'}); location.href='/'; }

const HCOLOR={healthy:'#41b866',degraded:'#e0a13a',failing:'#e0574f',silent:'#c98a2c',idle:'#5c6675',running:'#f2a45a'};
function pollHealthDot(){
  const tick=async()=>{ try{ const h=await (await fetch('/api/health')).json();
    const d=document.getElementById('healthDot'); if(d){ d.style.background=HCOLOR[h.overall]||'#5c6675';
      d.title='system health: '+h.overall; } }catch(e){} };
  tick(); setInterval(tick, 5000);
}
