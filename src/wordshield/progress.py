"""Progress uses completed work, never a simulated countdown."""
from time import time


def progress_snapshot(progress, state, now=None):
    now = time() if now is None else now
    stages = progress.get('stages', {})
    total = sum(s['total'] for s in stages.values())
    done = sum(min(s['done'], s['total']) for s in stages.values())
    finished = state in {'review', 'exported'}
    percent = 100 if finished else min(99, int(98 * done / total)) if total else None
    active = progress.get('active')
    stage = stages.get(active, {})
    advanced = stage.get('done', 0) - stage.get('baseline', 0)
    elapsed = max(0, now - stage.get('started', now))
    stale = bool(stage and now - stage.get('updated', now) > 60)
    eta = None
    if state == 'detecting' and advanced > 0 and not stale and stage['done'] < stage['total']:
        eta = round(elapsed / advanced * (stage['total'] - stage['done']))
    return {'percent': percent, 'stage_remaining_seconds': eta,
            'waiting_for_progress': stale, 'finished': finished}


ANALYSIS_PAGE = """<h1>Идёт локальный анализ</h1>
<p>Документ обрабатывается на офисном Mac mini и не отправляется в облако.</p>
<section class='analysis-card' aria-label='Прогресс анализа'>
<p id='analysis-stage'>Подготовка документа…</p>
<progress id='analysis-bar' max='100' aria-label='Выполненная работа' style='width:100%;height:18px;accent-color:#2863ff'></progress>
<p id='analysis-percent'>Ожидаем первые результаты…</p>
<p id='analysis-eta' role='status'>Оценка времени появится после первых обработанных фрагментов.</p>
<small>Время приблизительное: оно зависит от длины текста, загрузки моделей и других задач на Mac mini. Полоса показывает обработанные фрагменты всех детекторов, а не долю прошедшего времени.</small>
</section><p>После анализа страница откроет результаты автоматически. Можно вернуться через <a href='/sessions'>«Мои сессии»</a>.</p>
<script>(()=>{
const names={'queued':'Файл в очереди','detecting':'Подготовка и загрузка моделей','privacy-detector':'Поиск персональных данных','context-analysis':'Проверка контекста','russian-detector':'Проверка русских имён и реквизитов','combining':'Объединение результатов'};
const stage=document.getElementById('analysis-stage'),bar=document.getElementById('analysis-bar'),percent=document.getElementById('analysis-percent'),eta=document.getElementById('analysis-eta');
async function poll(){
try{
const r=await fetch('/api/sessions/__SID__/status',{cache:'no-store',signal:AbortSignal.timeout(15000)});
if(!r.ok)throw new Error();
const s=await r.json(),p=s.progress||{};
if(s.state==='review'||s.state==='exported'||s.state==='failed'){location.reload();return;}
stage.textContent=(names[s.stage]||'Обработка документа')+(s.total_chunks?' · '+s.completed_chunks+' из '+s.total_chunks+' фрагментов':'');
if(p.percent==null){bar.removeAttribute('value');percent.textContent='Подготовка к анализу…';}else{bar.value=p.percent;percent.textContent='Выполнено '+p.percent+'%';}
if(s.stage==='combining'){eta.textContent='Детекторы завершили работу. Подготавливаем список замен…';}
else if(p.waiting_for_progress){eta.textContent='Обработка продолжается, но новых результатов пока нет. Оценка времени уточняется.';}
else if(p.stage_remaining_seconds!=null){const n=p.stage_remaining_seconds;eta.textContent='До конца текущего этапа: примерно '+(n<60?'меньше минуты':Math.ceil(n/60)+' мин.')+' Остальные этапы могут потребовать дополнительного времени.';}
else{eta.textContent='Запуск модели или ожидание очереди. Оценка времени появится после первых обработанных фрагментов.';}
}catch(e){eta.textContent='Не удалось обновить статус. Проверяем связь; повторно загружать файл не нужно.';}
setTimeout(poll,2000);
}poll();})();</script>"""
