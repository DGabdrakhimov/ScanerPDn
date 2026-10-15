({action, click=false}) => {
 const names={reject:['отклонить все','отказаться от всех','reject all'],accept:['принять все','разрешить все','accept all'],revoke:['отозвать согласие','отозвать согласие на cookie','withdraw consent','withdraw cookie consent']};
 const roots=[document],nodes=[];
 for(let i=0;i<roots.length&&i<100;i++)for(const e of roots[i].querySelectorAll('*')){
  if(nodes.length>=20000)break;nodes.push(e);if(e.shadowRoot)roots.push(e.shadowRoot);
 }
 const norm=s=>(s||'').replace(/\s+/g,' ').trim().toLowerCase();
 const visible=e=>!!e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden';
 const eligible=[],candidates=[];let considered=0;
 for(const e of nodes){
  if(!e.matches('button,a[href],input[type="button"],input[type="submit"],input[type="checkbox"],input[type="radio"],[role="button"],[role="checkbox"],[role="switch"],select'))continue;
  const root=e.getRootNode();
  const labels=[...(e.labels?Array.from(e.labels):[]),...(e.getAttribute('aria-labelledby')||'').split(/\s+/).map(id=>root.getElementById?.(id)).filter(Boolean)];
  const text=norm(labels.map(l=>l.textContent).join(' ')||e.getAttribute('aria-label')||e.textContent||(e.matches('input[type="button"],input[type="submit"]')?e.value:''));
  const box=e.closest('[role="dialog"],[id*="cookie" i],[class*="cookie" i]');
  const cookie=!!box&&/cookie|куки/i.test(box.textContent||'');
  if(!cookie&&!Object.values(names).some(list=>list.includes(text))&&!/cookie|куки|персональн|соглас|принима|consent|accept|reject|отказ|отклон|privacy/i.test(text)&&!e.matches('input[type="checkbox"],input[type="radio"],[role="checkbox"],[role="switch"]'))continue;
  considered++;if(candidates.length>=200)continue;
  const actions=Object.keys(names).filter(k=>names[k].includes(text));
  const reasons=[];
  if(!visible(e))reasons.push('element_hidden');
  if(e.disabled||e.getAttribute('aria-disabled')==='true')reasons.push('element_disabled');
  if(e.form||e.closest('form'))reasons.push('element_in_form');
  if(!e.matches('button[type="button"]'))reasons.push('element_type_unsupported');
  if(!cookie)reasons.push('cookie_context_missing');
  if(action&&!actions.includes(action))reasons.push('action_label_mismatch');
  if(!actions.length)reasons.push('label_not_supported');
  candidates.push({index:candidates.length,kind:e.getAttribute('role')||e.tagName.toLowerCase(),input_type:e.matches('input,button')?e.type:null,label:text.slice(0,1200),visible:visible(e),disabled:!!e.disabled||e.getAttribute('aria-disabled')==='true',associated:labels.length>0||!!e.getAttribute('aria-label'),cookie_context:cookie,recognized_actions:actions,reasons});
  if(!reasons.length)eligible.push(e);
 }
 const limited=nodes.length>=20000||roots.length>=100||considered>200;
 const reason=limited?'diagnostic_limit':eligible.length>1?'ambiguous_buttons':eligible.length===0?(candidates.length?'no_eligible_button':'no_consent_elements'):null;
 let status=reason?'unsupported':'ready';
 if(click&&!reason){eligible[0].click();status='clicked';}
 return {status,count:eligible.length,reason,limited,candidates};
}
