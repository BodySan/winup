# Сторонние компоненты

## KeePassLib (ядро хранилища паролей)

- **Продукт:** KeePass Password Safe, библиотека KeePassLib
- **Автор:** Dominik Reichl
- **Версия:** 2.61.1 (официальный Source Code Package)
- **Источник:** https://keepass.info/download.html → «KeePass 2.61.1 Source Code Package»
  (прямая ссылка https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.61.1/KeePass-2.61.1-Source.zip/download)
- **Контрольная сумма архива (SHA-256, со страницы https://keepass.info/integrity.html):**
  `711BD9EC7076661678469E51BAE876DEBAC07A08C32F1B1C6B3B8FE5E761C13A`
  Размер: 5 333 853 байт. Сверено при сборке 04.10.2026.
- **Лицензия:** GPL v2 или более поздняя (файлы лицензий — в Docs/License.html архива исходников).
- **Сборка:** исходники KeePassLib не изменялись; библиотека собрана компилятором
  .NET Framework 4 (csc, C#5) из неизменённых файлов списка KeePassLib_N48.csproj
  (112 файлов, 0 ошибок). Результат: `src\lib\KeePassLib.dll`.
- **Поставка:** библиотека вшита в WinUp.exe как ресурс (отдельный файл не нужен). Обновление
  кнопкой «О программе → Проверить обновление крипто-ядра» использует подписанный KeePass.exe
  из официального переносного пакета. Проверяются SHA-256 пакета с keepass.info и подпись
  издателя KeePass; проверенные байты сохраняются в `data\core\KeePassLib.dll`.
- **Использование:** WinUp хранит базу паролей в стандартном формате KDBX 4 через KeePassLib
  (Argon2). WinUp распространяется вместе с исходным кодом под GPL v3 или более поздней.

## Cryptomator: файловое хранилище

- Оригинальные, неизменённые CryptoFS 2.8.0 и Cryptolib 2.2.0; формат Cryptomator 8,
  SIV_GCM. Монтирование: fuse-nio-adapter 5.0.5, jfuse 0.7.3.
- Библиотеки и Java 24 взяты из официального cryptomator-cli 0.6.2 для Windows x64:
  https://github.com/cryptomator/cli/releases/tag/0.6.2
- SHA-256 исходного бинарного архива:
  `52498FE6C0A02F76216FA801A1A114DE064B4364702E51548585355FDF8B0A66`.
  Проверена PGP-подпись Cryptobot; отпечаток ключа
  `58117AFA1F85B3EEC154677D615D449FE6E6A235` сверяется с
  https://docs.cryptomator.org/security/verify-installers/.
- Файловый процесс WinUpFiles — адаптер WinUp под AGPL v3; исходник:
  `vendor/file-engine/WinUpFiles.java`. Он вызывает оригинальные API и не меняет алгоритмы.
  У него нет собственного интерфейса и сетевого сервера. Пароль передаётся через stdin.
- Исходники соответствующих версий: `vendor/upstream/cryptofs-2.8.0.zip`,
  `cryptolib-2.2.0.zip`, `fuse-nio-5.0.5.zip`, `jfuse-0.7.3.zip`; контрольные суммы
  всех вложенных архивов — `vendor/upstream/SHA256.json`.
  Оригинальные проекты: https://github.com/cryptomator/cryptofs,
  https://github.com/cryptomator/cryptolib, https://github.com/cryptomator/fuse-nio-adapter,
  https://github.com/cryptomator/jfuse. Полные лицензии — `licenses/`; лицензии Java и
  остальных оригинальных зависимостей сохранены в файловом runtime.
- Для пересборки адаптера нужен JDK 24 либо ECJ 3.42.0 с встроенным runtime.
  В исходном пакете: `vendor/file-engine/build.ps1 -Jdk24 <путь к JDK 24>`;
  в рабочем репозитории также `qa/security/build-file-engine.ps1` для ECJ. Обычная сборка WinUp
  использует включённый в исходники `file-engine/file-engine.zip` и проверяет каждый
  его файл по встроенному SHA-256 перед запуском.

## WinFsp: диск в Проводнике

- WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos.
  https://github.com/winfsp/winfsp/releases/tag/v2.1
- Оригинальный MSI 2.1: SHA-256
  `073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A`.
  Перед установкой проверяются этот хэш и подпись NAVIMATICS LLC.
- GPL v3 с исключением для FLOSS, полный текст: `licenses/WinFsp.txt`.
  Установка необязательна; выполняется после выбора пользователя, требует администратора.

## Ключи доступа

- Криптографические помощники исходного KeePassPasskey:
  https://github.com/yusei36/KeePassPasskey, GPL v3 или более поздняя.
  Архив оригинала: `vendor/upstream/KeePassPasskey.zip` (SHA-256 в SHA256.json).
  Адаптированные файлы: `vendor/passkeys/`; изменения синтаксиса пространств имён
  и отдельный Adapter.cs для WinUp. Ни MSIX, ни внешний системный поставщик не устанавливаются.
- MAIN-world WebAuthn-обёртка собственного расширения адаптирована из KeePassXC-Browser:
  https://github.com/keepassxreboot/keepassxc-browser, GPL v3.
  Оригинал: `vendor/upstream/keepassxc-browser.zip`; адаптер транспорта —
  `browser/passkeys.js`, `browser/passkey-relay.js`. Стороннее расширение не требуется.
- BouncyCastle.Cryptography 2.6.2 (MIT), PeterO.Cbor 4.5.5 и PeterO.Numbers 1.8.2
  (CC0-1.0 по опубликованным NuGet-пакетам), оригинальные DLL для .NET Framework.
  Источники: https://www.nuget.org/packages/BouncyCastle.Cryptography/2.6.2,
  https://www.nuget.org/packages/PeterO.Cbor/4.5.5,
  https://www.nuget.org/packages/PeterO.Numbers/1.8.2.
  Компоненты вшиты в WinUp.exe, загрузка одноимённых соседних DLL отклоняется.
- Public Suffix List: https://publicsuffix.org/list/public_suffix_list.dat,
  MPL 2.0 (уведомление сохранено в файле). Включает частные суффиксы, например github.io.
- Сборка адаптера современным Roslyn для .NET Framework:
  `vendor/passkeys/build.ps1` в исходном пакете. Обычный `build.ps1`
  использует включённые DLL и системный компилятор .NET Framework.

## Прочее

- .NET Framework 4.x — системный компонент Windows.
- Основной интерфейс, автоввод, буфер и импорт 2FA — код WinUp.
- Лицензии доступны также в приложении: «О программе» → «Компоненты и лицензии».
