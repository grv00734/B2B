/** The single-page Aegis control panel (iOS Control Center style), served by src/gui.ts. */
export function dashboardHtml(): string {
  return PAGE;
}

const SHIELD =
  '<svg viewBox="0 0 24 24" width="26" height="26" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9-8 11-4.6-2-8-6-8-11V5l8-3z" fill="currentColor"/></svg>';

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
<title>Aegis</title>
<style>
  :root{
    --green:#34c759; --blue:#0a84ff; --red:#ff453a; --amber:#ff9f0a;
    --txt:#f5f5f7; --sub:rgba(235,235,245,.6); --glass:rgba(40,40,52,.55);
    --glass2:rgba(70,70,84,.45); --stroke:rgba(255,255,255,.16);
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{height:100%}
  body{margin:0;color:var(--txt);
    font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:15px;line-height:1.4;
    background:
      radial-gradient(circle at 12% 18%, #7b2ff7 0%, transparent 42%),
      radial-gradient(circle at 88% 12%, #0a84ff 0%, transparent 46%),
      radial-gradient(circle at 82% 88%, #16c2a3 0%, transparent 42%),
      radial-gradient(circle at 18% 92%, #ff2d75 0%, transparent 44%),
      #0a0a12;
    background-attachment:fixed;}
  .wrap{max-width:760px;margin:0 auto;padding:22px 16px 40px}
  .titlebar{display:flex;align-items:center;justify-content:space-between;margin:6px 4px 16px}
  .titlebar h1{font-size:22px;font-weight:700;letter-spacing:.3px;margin:0}
  .titlebar h1 small{display:block;font-size:12px;font-weight:500;color:var(--sub);letter-spacing:.2px}
  .pills{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}
  .pill{font-size:11px;color:var(--sub);background:var(--glass);border:1px solid var(--stroke);
    border-radius:999px;padding:4px 9px;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}

  .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .module{background:var(--glass);border:1px solid var(--stroke);border-radius:24px;padding:16px;
    backdrop-filter:blur(26px) saturate(150%);-webkit-backdrop-filter:blur(26px) saturate(150%);
    box-shadow:0 10px 34px rgba(0,0,0,.32)}
  .module h2{margin:0 0 12px;font-size:12px;font-weight:600;text-transform:uppercase;
    letter-spacing:.7px;color:var(--sub)}
  .span2{grid-column:1 / -1}

  /* connectivity-style round toggles */
  .conn{display:flex;gap:14px}
  .conn .item{display:flex;align-items:center;gap:12px;flex:1;min-width:0}
  .round{width:54px;height:54px;border-radius:50%;border:0;cursor:pointer;flex:0 0 auto;
    display:flex;align-items:center;justify-content:center;color:var(--sub);
    background:var(--glass2);transition:all .18s ease}
  .round.on{color:#fff;background:var(--green);box-shadow:0 0 0 4px rgba(52,199,89,.25),0 6px 18px rgba(52,199,89,.4)}
  .round.blue.on{background:var(--blue);box-shadow:0 0 0 4px rgba(10,132,255,.25),0 6px 18px rgba(10,132,255,.4)}
  .conn .txt{min-width:0}
  .conn .txt b{font-weight:600;font-size:15px}
  .conn .txt small{display:block;color:var(--sub);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  /* segmented control */
  .segmented{display:flex;background:rgba(0,0,0,.28);border-radius:12px;padding:3px;gap:3px}
  .segmented button{flex:1;border:0;background:transparent;color:var(--txt);font-size:13px;font-weight:600;
    padding:8px 4px;border-radius:9px;cursor:pointer;transition:.15s}
  .segmented button.on{background:rgba(255,255,255,.22)}

  /* iOS switch */
  .srow{display:flex;align-items:center;justify-content:space-between;padding:9px 2px;
    border-bottom:1px solid rgba(255,255,255,.08)}
  .srow:last-child{border-bottom:0}
  .switch{position:relative;width:50px;height:30px;flex:0 0 auto}
  .switch input{opacity:0;width:0;height:0;position:absolute}
  .switch .sl{position:absolute;inset:0;background:rgba(120,120,128,.4);border-radius:999px;transition:.2s}
  .switch .sl:before{content:"";position:absolute;width:26px;height:26px;left:2px;top:2px;background:#fff;
    border-radius:50%;transition:.2s;box-shadow:0 2px 5px rgba(0,0,0,.35)}
  .switch input:checked + .sl{background:var(--green)}
  .switch input:checked + .sl:before{transform:translateX(20px)}

  textarea,input.text{width:100%;background:rgba(0,0,0,.28);color:var(--txt);border:1px solid var(--stroke);
    border-radius:14px;padding:11px 13px;font-size:14px;font-family:inherit;resize:vertical}
  textarea.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
  .btn{background:var(--blue);color:#fff;border:0;border-radius:12px;padding:9px 16px;font-size:14px;
    font-weight:600;cursor:pointer}
  .btn.sub{background:rgba(255,255,255,.16)}
  .hint{color:var(--sub);font-size:12px;margin:2px 2px 12px}

  pre{background:rgba(0,0,0,.3);border:1px solid var(--stroke);border-radius:14px;padding:12px;margin:0;
    white-space:pre-wrap;word-break:break-word;font-size:12.5px;max-height:200px;overflow:auto;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .findings{list-style:none;margin:0;padding:0;max-height:200px;overflow:auto}
  .findings li{display:flex;align-items:center;gap:9px;padding:9px 11px;background:rgba(0,0,0,.22);
    border-radius:12px;margin-bottom:8px;font-size:12.5px}
  .sev{font-size:10px;font-weight:800;padding:3px 8px;border-radius:999px;text-transform:uppercase;flex:0 0 auto}
  .sev.critical{background:rgba(255,69,58,.22);color:#ff8a80}
  .sev.high{background:rgba(255,159,10,.22);color:#ffcf70}
  .sev.medium{background:rgba(10,132,255,.22);color:#7fbcff}
  .sev.low{background:rgba(120,120,128,.28);color:#c7c7cc}
  .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--sub)}
  .activity{list-style:none;margin:0;padding:0;max-height:260px;overflow:auto}
  .activity li{display:flex;gap:9px;align-items:center;padding:9px 4px;border-bottom:1px solid rgba(255,255,255,.07);font-size:12.5px}
  .tag{font-size:10px;font-weight:800;padding:2px 8px;border-radius:999px;flex:0 0 auto}
  .tag.REDACT{background:rgba(10,132,255,.22);color:#7fbcff}
  .tag.BLOCK{background:rgba(255,69,58,.22);color:#ff8a80}
  .tag.WARN{background:rgba(255,159,10,.22);color:#ffcf70}
  .tag.CLEAN{background:rgba(52,199,89,.22);color:#7ee29a}
  .empty{color:var(--sub);font-style:italic;padding:6px 2px}
  .saved{color:var(--green);font-size:12px;margin-left:10px}
  @media(max-width:680px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="titlebar">
    <h1>Aegis<small>Confidential Data Guard</small></h1>
    <div class="pills" id="pills"></div>
  </div>

  <div class="grid">
    <section class="module">
      <h2>Guard</h2>
      <div class="conn">
        <div class="item">
          <button class="round" id="toggleBase">${SHIELD}</button>
          <div class="txt"><b>Base-URL</b><small id="urlBase">Off</small></div>
        </div>
        <div class="item">
          <button class="round blue" id="toggleSystem">${SHIELD}</button>
          <div class="txt"><b>System</b><small id="urlSystem">Off</small></div>
        </div>
      </div>
    </section>

    <section class="module">
      <h2>Action on detection</h2>
      <div class="segmented" id="segMode">
        <button data-mode="redact">Redact</button>
        <button data-mode="block">Block</button>
        <button data-mode="warn">Warn</button>
      </div>
      <p class="hint" style="margin-top:12px;margin-bottom:0">Redact swaps secrets for placeholders and restores them in the reply. Block refuses the request.</p>
    </section>

    <section class="module">
      <h2>Detectors</h2>
      <div id="detectors"></div>
    </section>

    <section class="module">
      <h2>Company dictionary</h2>
      <textarea id="dictionary" rows="4" placeholder="Project Phoenix&#10;acme-internal.com"></textarea>
      <div style="display:flex;align-items:center;margin-top:10px">
        <button class="btn sub" id="btnDict">Apply</button>
        <span class="saved" id="savedMsg"></span>
      </div>
    </section>

    <section class="module span2">
      <h2>Live redaction tester</h2>
      <p class="hint">Paste anything an employee might send to an AI. Detection runs locally — nothing leaves this machine.</p>
      <textarea id="input" class="mono" rows="5" placeholder="Paste a .env, config, code, or notes here..."></textarea>
      <div class="grid" style="margin-top:12px">
        <div>
          <div class="hint" style="margin:0 0 6px">What the AI would receive</div>
          <pre id="redacted" class="empty">—</pre>
        </div>
        <div>
          <div class="hint" style="margin:0 0 6px">Findings (<span id="count">0</span>)</div>
          <ul class="findings" id="findings"><li class="empty">No findings yet.</li></ul>
        </div>
      </div>
    </section>

    <section class="module span2">
      <h2>Activity</h2>
      <ul class="activity" id="activity"><li class="empty">Waiting for traffic — start a guard and send a request.</li></ul>
    </section>
  </div>
</div>

<script>
  var DETECTORS=["secrets","pii","identity","network","dictionary","code"];
  function $(id){return document.getElementById(id)}
  function api(p,m,b){return fetch(p,{method:m||"GET",headers:{"content-type":"application/json"},
    body:b?JSON.stringify(b):undefined}).then(function(r){return r.json()})}
  function esc(s){return String(s).replace(/[&<>]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c]})}
  function setConfig(part){return api("/api/config","POST",part).then(renderStatus)}

  var current={};
  function renderStatus(s){
    current=s;
    $("toggleBase").classList.toggle("on",!!s.base);
    $("toggleSystem").classList.toggle("on",!!s.system);
    $("urlBase").textContent=s.base?s.baseUrl.replace("http://",""):"Off";
    $("urlSystem").textContent=s.system?s.systemUrl.replace("http://",""):"Off";
    $("pills").innerHTML=
      '<span class="pill">'+(s.base?"Base-URL on":"Base-URL off")+'</span>'+
      '<span class="pill">'+(s.system?"System on":"System off")+'</span>'+
      '<span class="pill">mode '+esc(s.mode)+'</span>';
    Array.prototype.forEach.call($("segMode").children,function(b){
      b.classList.toggle("on",b.dataset.mode===s.mode)});
    renderDetectors(s.detectors);
    if(document.activeElement!==$("dictionary")) $("dictionary").value=(s.dictionary||[]).join("\\n");
  }
  function renderDetectors(d){
    if(!$("detectors").dataset.built){
      $("detectors").innerHTML=DETECTORS.map(function(k){
        return '<label class="srow"><span>'+k+'</span><span class="switch">'+
          '<input type="checkbox" id="det_'+k+'"/><span class="sl"></span></span></label>'}).join("");
      $("detectors").dataset.built="1";
      DETECTORS.forEach(function(k){$("det_"+k).addEventListener("change",saveDetectors)});
    }
    DETECTORS.forEach(function(k){var c=$("det_"+k);if(c&&document.activeElement!==c)c.checked=!!d[k]});
  }
  function saveDetectors(){
    var det={};DETECTORS.forEach(function(k){det[k]=$("det_"+k).checked});
    setConfig({detectors:det}).then(function(){scan()});
  }

  $("toggleBase").addEventListener("click",function(){
    api(current.base?"/api/proxy/stop":"/api/proxy/start","POST",{kind:"base"}).then(renderStatus)});
  $("toggleSystem").addEventListener("click",function(){
    api(current.system?"/api/proxy/stop":"/api/proxy/start","POST",{kind:"system"}).then(renderStatus)});
  Array.prototype.forEach.call($("segMode").children,function(b){
    b.addEventListener("click",function(){setConfig({mode:b.dataset.mode}).then(scan)})});
  $("btnDict").addEventListener("click",function(){
    var dict=$("dictionary").value.split("\\n").map(function(x){return x.trim()}).filter(Boolean);
    setConfig({dictionary:dict}).then(function(){
      $("savedMsg").textContent="Saved";setTimeout(function(){$("savedMsg").textContent=""},1400);scan()})});

  var t;
  function scan(){
    var text=$("input").value;
    if(!text){$("redacted").textContent="—";$("redacted").className="empty";
      $("findings").innerHTML='<li class="empty">No findings yet.</li>';$("count").textContent="0";return}
    api("/api/scan","POST",{text:text}).then(function(r){
      $("redacted").textContent=r.redacted;$("redacted").className="";
      $("count").textContent=r.findings.length;
      if(!r.findings.length){$("findings").innerHTML='<li class="empty">No confidential data detected.</li>';return}
      $("findings").innerHTML=r.findings.map(function(f){
        return '<li><span class="sev '+f.severity+'">'+f.severity+'</span>'+
          '<span class="grow">'+esc(f.category)+" / "+esc(f.type)+'</span>'+
          '<span class="mono">'+esc(f.preview)+'</span></li>'}).join("")})}
  $("input").addEventListener("input",function(){clearTimeout(t);t=setTimeout(scan,300)});

  function addActivity(e){
    var ul=$("activity");var em=ul.querySelector(".empty");if(em)em.remove();
    var types=Object.keys(e.summary.byType||{}).map(function(k){return k+"×"+e.summary.byType[k]}).join(", ");
    var tag=e.action==="blocked"?"BLOCK":e.action==="redacted"?"REDACT":e.action==="warned"?"WARN":"CLEAN";
    var li=document.createElement("li");
    li.innerHTML='<span class="tag '+tag+'">'+tag+'</span>'+
      '<span class="mono">'+esc((e.ts||"").replace("T"," ").replace(/\\..*/,""))+'</span>'+
      '<span class="grow">'+esc(e.route||"")+(e.direction==="response"?" - response":"")+'</span>'+
      '<span class="mono">'+esc(types)+'</span>';
    ul.insertBefore(li,ul.firstChild);
    while(ul.children.length>50)ul.removeChild(ul.lastChild)}

  var ev=new EventSource("/api/events");
  ev.onmessage=function(m){var e=JSON.parse(m.data);
    if(e.type==="status")renderStatus(e.status);else if(e.type==="audit")addActivity(e.entry)};
  api("/api/status").then(renderStatus);
  api("/api/audit").then(function(r){(r.entries||[]).slice().reverse().forEach(addActivity)});
</script>
</body>
</html>`;
