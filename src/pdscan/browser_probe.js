() => {
 const roots=[document], nodes=[];
 for(let i=0;i<roots.length && i<100;i++) for(const e of roots[i].querySelectorAll('*')) {
  if(nodes.length>=20000) break;
  nodes.push(e); if(e.shadowRoot) roots.push(e.shadowRoot);
 }
 const visible=e=>!!(e.getClientRects().length) && getComputedStyle(e).visibility!=='hidden';
 const clean=s=>(s||'').replace(/\s+/g,' ').trim().slice(0,1200);
 const consent=s=>/согласи[еяю]|согласен|согласна|consent/i.test(s)&&/персональн|personal data/i.test(s);
 const policy=s=>/политик[^.]{0,80}(?:персональн|конфиденциальн)|privacy policy/i.test(s);
 const advertising=s=>/реклам|marketing|advertis/i.test(s);
 const controls=[];
 const controlNodes=nodes.filter(e=>e.matches('input[type="checkbox"],input[type="radio"],[role="checkbox"],[role="switch"]'));
 const docNodes=nodes.filter(e=>e.matches('a[href]')&&visible(e)).filter(e=>policy(clean(e.textContent))||consent(clean(e.textContent)));
 let storageLimited=false;
 for(const e of controlNodes.slice(0,200)) {
  let labels=e.labels?Array.from(e.labels):[];
  const root=e.getRootNode();
  const ids=(e.getAttribute('aria-labelledby')||'').split(/\s+/).filter(Boolean);
  const aria=ids.map(id=>root.getElementById?.(id)).filter(Boolean);
  const label=clean([...labels,...aria].map(x=>x.textContent).join(' ')||e.getAttribute('aria-label')||(e.getAttribute('role')?e.textContent:''));
  const links=[...labels,...aria].flatMap(x=>Array.from(x.querySelectorAll('a[href]'))).slice(0,20).map(a=>({url:a.href,label:clean(a.textContent)}));
  const negative=/\bnot\b|не\s+(соглас|принима|даю)/i.test(label);
  controls.push({index:controls.length,kind:e.getAttribute('role')||e.type,visible:visible(e),disabled:!!e.disabled||e.getAttribute('aria-disabled')==='true',checked:e.matches('input')?e.checked:e.getAttribute('aria-checked')==='true'?true:e.getAttribute('aria-checked')==='false'?false:null,initial_checked:e.matches('input')?e.defaultChecked:null,label,links,association:!!(labels.length||aria.length||e.getAttribute('aria-label')),consent:consent(label),marketing:advertising(label),combined:!negative&&consent(label)&&(/принимаю\s+(?:условия\s+)?оферт|соглас(?:ен|на)\s+с\s+(?:условиями\s+)?оферт|accept\s+(?:the\s+)?terms/i.test(label)),negative});
 }
 const documents=docNodes.slice(0,100).map(e=>({url:e.href,label:clean(e.textContent),type:policy(clean(e.textContent))&&!consent(clean(e.textContent))?'policy':consent(clean(e.textContent))&&!policy(clean(e.textContent))?'consent':'unknown'}));
 let storage=[];try{storage=Object.keys(localStorage).slice(0,200);storageLimited=localStorage.length>200}catch{}
 return {controls,documents,storage,limited:nodes.length>=20000||roots.length>=100||controlNodes.length>200||docNodes.length>100||storageLimited,frames:document.querySelectorAll('iframe').length};
}
