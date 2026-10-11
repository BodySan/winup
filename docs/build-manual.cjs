const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const uiRoot = path.resolve(__dirname, '..'), assets = path.join(__dirname, 'screens');
const captions = {
  passwords: 'Пароли: список аккаунтов, фильтры, карточка и команды выбранной записи.',
  'passwords-light': 'Главное окно в светлой теме.',
  'sticky-account': 'Карточка аккаунта остаётся видимой в конце длинного списка.',
  settings: 'Настройки: браузер, блокировка, трей, уведомления и смена темы.',
  'application-actions': 'Действия приложения: экспорт, перенос, защита базы и подключение расширения.',
  'create-database': 'Создание базы: пароль, ключ-файл и папка резервных копий.',
  entry: 'Редактирование аккаунта: тип записи, адреса, приложение, основной и дополнительный логин.',
  'entry-template': 'Добавление аккаунта: поиск шаблона и фильтры по типу и категории.',
  'entry-options': 'Нижняя часть записи: 2FA, ключ доступа, резервные коды, заметка и правила входа.',
  addresses: 'Проверка адресов: настройки, сайт, страница входа и предлагаемые исправления.',
  import: 'Импорт: новые записи, найденные дубли и выбор записей для добавления.',
  groups: 'Управление группами аккаунтов.',
  attachments: 'Вложения к выбранному аккаунту.',
  generator: 'Генератор пароля и фразы: настройки, копирование и новый вариант.',
  'protected-fields': 'Дополнительные защищённые поля выбранной записи.',
  'record-history': 'История записи и корзина базы.',
  'password-actions': 'Все действия вкладки «Пароли».',
  'browser-setup': 'Подключение расширения: выбранный браузер, адрес его страницы и кнопки открытия и копирования.',
  otp: '2FA: текущие коды, оставшееся время и действия с выбранным аккаунтом.',
  'otp-editor': 'Добавление 2FA: название, секрет и параметры кода.',
  passkeys: 'Ключи доступа: список, создание через сайт и подключение к Windows.',
  'passkey-create': 'Добавление ключа: выбор сервиса и переход на сайт для создания.',
  files: 'Файлы: выбор хранилища, папки, документы и команды отдельного шифрования.',
  'file-import': 'Добавление в хранилище: копирование или перенос исходников.',
  'files-locked': 'Закрытое файловое хранилище и кнопка открытия.',
  'package-password': 'Отдельный пакет: пароль, повтор и выбор удаления исходников.',
  'file-export': 'Выгрузка: зашифрованный пакет или обычная копия.',
  'file-settings': 'Настройки хранилища: диск, история, резерв, редактор и режим проекта.',
  'database-locked': 'Закрытая база паролей. Файловые хранилища управляются отдельно.',
  run: 'Запуск: программы и действия с выбранной записью.',
  winget: 'WinGet: поиск в каталоге, мой набор, обновления и установка отмеченных пакетов.',
  install: 'Установка: собственные установщики, отметки и режим запуска.',
  download: 'Скачать: сохранённые ссылки на сайты программ.',
  components: 'Компоненты: текущие и доступные версии, состояния и журнал.',
  export: 'Экспорт паролей: выбор форматов и папки сохранения.'
};
fs.mkdirSync(assets, { recursive: true });
const input = process.argv.indexOf('--capture-dir');
if (input >= 0) {
  const source = path.resolve(process.argv[input + 1]);
  const checks = JSON.parse(fs.readFileSync(path.join(source, 'document-capture.json'), 'utf8'));
  if (checks.some(c => !c.passed)) throw Error('Document capture did not complete.');
  for (const name of Object.keys(captions)) {
    if (name === 'sticky-account') continue;
    const file = path.join(source, name + '.png');
    if (fs.existsSync(file)) fs.copyFileSync(file, path.join(assets, name + '.png'));
  }
}
const escape = text => text.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const used = new Set(), images = [];
let html = fs.readFileSync(path.join(__dirname, 'manual-template.html'), 'utf8');
html = html.replace(/\{\{shot:([\w-]+)\}\}/g, (_, name) => {
  if (!captions[name]) throw Error('Unknown image: ' + name);
  if (used.has(name)) throw Error('Repeated image: ' + name);
  used.add(name);
  const png = fs.readFileSync(path.join(assets, name + '.png'));
  if (!png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw Error('Invalid PNG: ' + name);
  images.push({ name, width: png.readUInt32BE(16), height: png.readUInt32BE(20), sha256: crypto.createHash('sha256').update(png).digest('hex') });
  const caption = escape(captions[name]);
  return `<figure><button class="figure-open" type="button" aria-label="Увеличить: ${caption}"><img alt="${caption}" loading="lazy" width="${png.readUInt32BE(16)}" height="${png.readUInt32BE(20)}" src="data:image/png;base64,${png.toString('base64')}"></button><figcaption>${caption}</figcaption></figure>`;
});
html = html.replace('</style>', `.figure-open{display:block;width:100%;padding:0;border:0;background:transparent;cursor:zoom-in;text-align:left}.figure-open img{width:auto;max-width:100%;height:auto}.figure-open:focus-visible{outline:3px solid var(--accent);outline-offset:5px}td,th{overflow-wrap:anywhere}.image-viewer{width:min(96vw,1450px);max-width:96vw;max-height:94dvh;padding:16px;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:10px}.image-viewer::backdrop{background:#000b}.viewer-head{display:flex;align-items:center;gap:12px;justify-content:space-between;margin-bottom:12px}.viewer-head p{margin:0;font-size:15px}.viewer-head button{flex:none}.image-frame{max-height:calc(94dvh - 110px);overflow:auto}.image-frame img{max-width:none;width:auto;height:auto}body:has(.image-viewer[open]){overflow:hidden}@media print{.image-viewer{display:none}}\n</style>`);
html = html.replace('</main>', `</main><dialog class="image-viewer" id="image-viewer" aria-label="Увеличенный снимок"><div class="viewer-head"><p id="image-caption"></p><button type="button" id="close-image">Закрыть · Esc</button></div><div class="image-frame"><img id="large-image" alt=""></div></dialog>`);
html = html.replace('</body>', `<script>(()=>{const viewer=document.getElementById('image-viewer'),large=document.getElementById('large-image');document.addEventListener('click',event=>{const button=event.target.closest('.figure-open');if(!button)return;const img=button.querySelector('img');large.src=img.src;large.alt=img.alt;document.getElementById('image-caption').textContent=img.alt;viewer.showModal();});document.getElementById('close-image').addEventListener('click',()=>viewer.close());viewer.addEventListener('close',()=>large.removeAttribute('src'));})();</script></body>`);
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
if (ids.length !== new Set(ids).size) throw Error('Repeated document IDs.');
const broken = [...html.matchAll(/href="#([^"]+)"/g)].map(m => m[1]).filter(id => !ids.includes(id));
if (broken.length) throw Error('Broken document links: ' + broken.join(', '));
if (/BSanzharov|BodyaScamm|BODYAS~1|\{\{shot:/.test(html)) throw Error('Private name or unresolved placeholder in document.');
for (const file of [path.join(uiRoot, 'src/help.html'), path.join(uiRoot, 'Инструкция.html'), path.join(uiRoot, 'doc/Инструкция.html')]) fs.writeFileSync(file, html);
fs.writeFileSync(path.join(__dirname, 'illustrations.json'), JSON.stringify({ images: images.length, files: images }, null, 2));
console.log('Instruction updated; ' + images.length + ' current screenshots, document links verified.');
