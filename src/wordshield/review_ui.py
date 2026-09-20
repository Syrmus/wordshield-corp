REVIEW_SCRIPT = """<script>(()=>{
const status=document.getElementById('save-status'), controls=()=>document.querySelectorAll('tr[data-id] input,tr[data-id] select,#manual-text,#manual-type,#add-fragment,.resolve-overlap');
const rowDecision=r=>({id:r.dataset.id,entity_type:r.querySelector('select').value,status:r.querySelector('.status').checked?'accepted':'rejected'});
let queue=Promise.resolve(),pending=0,failed=false,refresh=false,exporting=false,downloaded=false;
function save(decisions,additions=[]){
 pending++;status.textContent='Сохраняем…';
 const next=queue.catch(()=>{}).then(async()=>{
  const r=await fetch('/api/sessions/__SID__/decisions',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({decisions,additions}),signal:AbortSignal.timeout(30000)});
  if(!r.ok)throw new Error('Не удалось сохранить изменения. Проверьте связь и повторите действие.');
  if(r.json){const data=await r.json();if(data.findings){const rows=[...document.querySelectorAll('tr[data-id]')];refresh=rows.length!==data.findings.length||rows.some(row=>{const f=data.findings.find(x=>x.id===row.dataset.id);return !f||row.querySelector('.target')?.textContent!=='Фрагмент: '+f.exact_text;});}}
  failed=false;
 });
 queue=next;
 next.then(()=>{pending--;if(!pending){status.textContent='Все изменения сохранены';if(refresh&&!exporting)location.reload();}},e=>{pending--;failed=true;status.textContent=e.message||'Ошибка сохранения. Повторите действие.';});
 return next;
}
document.querySelectorAll('tr[data-id]').forEach(row=>row.querySelectorAll('input,select').forEach(control=>control.addEventListener('change',()=>{save([rowDecision(row)]).catch(()=>{});} )));
function lock(value){controls().forEach(c=>c.disabled=value);document.querySelectorAll('#export-form button').forEach(b=>b.disabled=value);}
document.getElementById('add-fragment').onclick=async()=>{
 const exact_text=document.getElementById('manual-text').value;if(!exact_text.trim()){status.textContent='Сначала введите точный фрагмент.';return;}
 lock(true);try{await save([...document.querySelectorAll('tr[data-id]')].map(rowDecision),[{exact_text,entity_type:document.getElementById('manual-type').value}]);location.reload();}catch(e){lock(false);}
};
document.getElementById('export-form').addEventListener('submit',async e=>{
 e.preventDefault();const form=e.currentTarget;
 const format=e.submitter?.dataset.format||'docx';
 form.action='/api/sessions/__SID__/export?format='+format;
 if(downloaded){form.submit();return;}
 if(document.getElementById('manual-text').value.trim()){status.textContent='Нажмите «Добавить фрагмент» или очистите поле перед экспортом.';return;}
 exporting=true;lock(true);try{await save([...document.querySelectorAll('tr[data-id]')].map(rowDecision));status.textContent='Решения сохранены. Готовим файл…';form.submit();downloaded=true;}catch(e){exporting=false;lock(false);}
 // The download does not navigate away. Let the user use the page again.
 setTimeout(()=>{lock(false);if(downloaded)controls().forEach(c=>c.disabled=true);},3000);
});
document.querySelectorAll('.resolve-overlap').forEach(button=>button.onclick=async()=>{
 for(const row of document.querySelectorAll('tr[data-id]')){if(row.dataset.id===button.dataset.keep)row.querySelector('.status').checked=true;if(row.dataset.id===button.dataset.drop)row.querySelector('.status').checked=false;}
 lock(true);try{await save([...document.querySelectorAll('tr[data-id]')].map(rowDecision));location.reload();}catch(e){lock(false);}
});
window.addEventListener('beforeunload',e=>{if(pending||failed){e.preventDefault();e.returnValue='';}});
})();</script>"""
