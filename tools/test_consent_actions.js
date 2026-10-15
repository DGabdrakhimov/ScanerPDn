// Contract tests with a DOM double; this is not a real browser.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync('src/pdscan/consent_actions.js','utf8');
let root;
function element({tag='button',type='button',text='Принять все',role=null,hidden=false,disabled=false,form=false,cookie=true,aria=null}={}){
 return {tagName:tag.toUpperCase(),type,textContent:text,disabled,form:form?{}:null,labels:[],clicked:0,
 getAttribute(n){return n==='role'?role:n==='aria-label'?aria:null},
 getClientRects(){return hidden?[]:[{}]},getRootNode(){return root},
 closest(s){return s==='form'?(form?{}:null):(cookie?{textContent:'Cookie настройки'}:null)},
 matches(selector){return selector.split(',').some(s=>{const m=s.trim().match(/^([a-z]+)?(?:\[([^=\]]+)(?:="([^"]*)")?\])?$/);return !!m&&(!m[1]||m[1]===tag)&&(!m[2]||(m[2]==='type'?type===m[3]:m[2]==='role'?role===m[3]:m[2]==='href'?tag==='a':false))})},
 click(){this.clicked++}};
}
function run(elements){root={querySelectorAll(){return elements},getElementById(){return null}};return vm.runInNewContext('('+source+')',{document:root,getComputedStyle:()=>({visibility:'visible'})})({action:'accept',click:true});}
let e=element();assert.equal(run([e]).status,'clicked');assert.equal(e.clicked,1);
let pair=[element(),element()];assert.equal(run(pair).reason,'ambiguous_buttons');assert.equal(pair[0].clicked+pair[1].clicked,0);
for(const [option,reason] of [['disabled','element_disabled'],['hidden','element_hidden'],['form','element_in_form']]){e=element({[option]:true});const r=run([e]);assert.equal(r.status,'unsupported');assert(r.candidates[0].reasons.includes(reason));assert.equal(e.clicked,0);}
e=element({tag:'a',type:null,aria:'Принять все'});assert(run([e]).candidates[0].reasons.includes('element_type_unsupported'));assert.equal(e.clicked,0);
e=element({tag:'div',type:null,role:'checkbox',text:'Согласен на обработку персональных данных'});assert.equal(run([e]).candidates[0].kind,'checkbox');assert.equal(e.clicked,0);
e=element({cookie:false});assert(run([e]).candidates[0].reasons.includes('cookie_context_missing'));
e=element({text:'Продолжить'});assert(run([e]).candidates[0].reasons.includes('label_not_supported'));
assert.equal(run([]).reason,'no_consent_elements');console.log('Consent action contract: 10 cases passed (DOM double; not Chromium).');
