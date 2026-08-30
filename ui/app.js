const $=s=>document.querySelector(s);
const nav=[...document.querySelectorAll('.nav')];
nav.forEach(b=>b.onclick=()=>{nav.forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));$('#'+b.dataset.page).classList.add('active');const titles={protect:['Защита файла','Настройте защиту и запустите обработку.'],analyze:['Анализ','Проверьте формат и свойства артефакта.'],profiles:['Профили защиты','Готовые режимы для разных сценариев.'],settings:['Настройки','Параметры движка и ограничений.']};$('#title').textContent=titles[b.dataset.page][0];$('#subtitle').textContent=titles[b.dataset.page][1]});
const file=$('#file'),drop=$('#drop'),selected=$('#selected'),btn=$('#protectBtn');
$('#choose').onclick=()=>file.click();
file.onchange=()=>select(file.files[0]);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.add('drag')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,x=>{x.preventDefault();drop.classList.remove('drag')}));
drop.ondrop=e=>select(e.dataTransfer.files[0]);
function select(f){if(!f)return;selected.textContent=`${f.name} · ${(f.size/1048576).toFixed(2)} MiB`;btn.disabled=false;}
btn.onclick=()=>{const p=$('#profile').value,bar=$('.progress'),fill=bar.firstElementChild,log=$('#log');bar.style.display='block';btn.disabled=true;fill.style.width='0';log.textContent='';let n=0;const steps=['Проверка входного файла…','Определение формата…','Проверка профиля…','Подготовка pipeline…','Проверка целостности…','Финальная валидация…'];const t=setInterval(()=>{log.textContent+=steps[n]+'\n';fill.style.width=((n+1)/steps.length*100)+'%';n++;if(n===steps.length){clearInterval(t);log.textContent+='Готово. Engine API подключите к UI-командам protect/analyze.';btn.disabled=false}},220)};
$('#analyzeBtn').onclick=()=>$('#analyzeFile').click();
$('#analyzeFile').onchange=e=>{const f=e.target.files[0];if(f)$('#analysis').textContent=`Файл: ${f.name}\nРазмер: ${f.size} bytes\nФормат: определение выполняется engine\nСтатус: готов к анализу`;};
$('#theme').onclick=()=>document.body.classList.toggle('light');
