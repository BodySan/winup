using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WinUp
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            // Режим моста Native Messaging: браузер запускает WinUp.exe "chrome-extension://<id>/".
            // Мост ничего не создаёт и окон не показывает: пересылает один запрос в открытое окно
            // WinUp (именованный канал) и возвращает один ответ. Выполняется до мьютекса и Run.
            if (args != null && args.Length > 0 && (args[0].StartsWith("chrome-extension://", StringComparison.OrdinalIgnoreCase) ||
                args.Length >= 2 && args[1] == BrowserSetup.FirefoxId && Proc.SameFile(args[0],BrowserSetup.FirefoxHostManifestPath)))
            {
                BrowserBridge.Run(args.Length >= 2 && args[1] == BrowserSetup.FirefoxId ? args[1] : args[0]);
                return;
            }

            ComponentResources.Initialize();

            // Версия KeePassLib меняется между сборками WinUp (крипто-ядро обновляется
            // без пересборки), а строгая ссылка на скомпилированную версию привела бы к
            // FileLoadException на обновлённой DLL. Ядро из своей папки загружаем сами:
            // результат обработчика разрешения сборок версией не проверяется.
            // Грузим из байтов — LoadFrom отказывает на файлах с меткой интернета
            // (Zone.Identifier: библиотека в папке могла прийти из скачанного архива KeePass).
            // Выбор ядра — CoreLoader: вшитое в exe или обновлённое в data\core (см. там же правила доверия).
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                if (new System.Reflection.AssemblyName(e.Name).Name != "KeePassLib") return EmbeddedModules.Resolve(e.Name);
                try { return CoreLoader.Resolve(); }
                catch { return null; }
            };

            // KeePassLib.dll рядом с exe (прежняя раскладка) Windows загрузила бы сама, мимо выбора ядра — убираем
            // до первого обращения к ядру.
            CoreLoader.MigrateLegacy();
            try { EmbeddedModules.RejectAdjacent(); }
            catch (Exception ex) { MessageBox.Show(ex.Message, "WinUp — проверка компонентов", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
            if (System.IO.File.Exists(System.IO.Path.Combine(Paths.Root, CoreLoader.FileName)))
            {
                MessageBox.Show("Не удалось убрать внешнюю KeePassLib.dll из папки программы.\nУберите её вручную перед запуском WinUp.",
                    "WinUp — проверка крипто-ядра", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // Перезапуск после обновления ядра: новый процесс ждёт смерти старого,
            // чтобы освободился мьютекс одного экземпляра и DLL в его процессе.
            int waitIdx = Array.IndexOf(args, "--wait");
            if (waitIdx >= 0 && waitIdx + 1 < args.Length)
            {
                int parent;
                if (int.TryParse(args[waitIdx + 1], out parent))
                {
                    try { System.Diagnostics.Process.GetProcessById(parent).WaitForExit(10000); }
                    catch { }
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            // Ошибка в обработчике не должна закрывать программу: показываем её и продолжаем.
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (s, e) =>
                MessageBox.Show(e.Exception.Message, "WinUp — ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);

            // Второй экземпляр из той же папки не запускается: два процесса на одной базе —
            // это потеря правок при сохранении и гонки на счётчиках попыток.
            // Исключение — режим --install: его запускает уже работающий экземпляр с правами
            // администратора (один UAC на всю пачку). Он только читает apps.json, не пишет его,
            // поэтому мьютекс его убивать не должен — иначе установка не запускается никогда.
            // Режим установки — это --install вместе со списком id; без списка это ошибка вызова, а не режим.
            // WinUp.exe --winget install|upgrade id1,id2 [--manual] — очередь winget с правами администратора
            // (один UAC на пачку). Ни базы, ни apps.json не трогает — мьютекс ей не нужен.
            int wgIdx = Array.IndexOf(args, "--winget");
            if (wgIdx >= 0)
            {
                if (wgIdx + 2 >= args.Length || (args[wgIdx + 1] != "install" && args[wgIdx + 1] != "upgrade"))
                {
                    MessageBox.Show("--winget требует действие и список ID (например: --winget install Mozilla.Firefox,7zip.7zip).",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                var wgIds = args[wgIdx + 2].Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
                Application.Run(new WingetForm(wgIds, args[wgIdx + 1], !args.Contains("--manual")));
                return;
            }

            int installIdx = Array.IndexOf(args, "--install");
            bool installMode = installIdx >= 0 && installIdx + 1 < args.Length;
            Mutex single = null;
            bool createdNew = false;
            if (!installMode)
            {
                try { single = new Mutex(true, "WinUp-" + FolderHash(Paths.Root), out createdNew); }
                catch (Exception ex)
                {
                    MessageBox.Show("WinUp не может создать служебный объект:\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (!createdNew)
                {
                    // Повторный запуск — обычно «где окно?»: выводим уже открытое окно вперёд, сообщение — если не нашли.
                    if (!Win.ActivateMainWindow("WinUp — " + Paths.Root))
                        MessageBox.Show("WinUp уже запущен из папки\n" + Paths.Root + "\n\nВторой экземпляр из той же папки не допускается.",
                            "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
            }
            try
            {
                // --install без списка id раньше проскакивал дальше и открывал второй MainForm без мьютекса.
                if (installIdx >= 0 && !installMode)
                {
                    MessageBox.Show("--install требует список id через запятую (например: --install id1,id2).",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                Run(args, installIdx);
            }
            finally { if (single != null) single.ReleaseMutex(); }
        }

        static void Run(string[] args, int installIdx)
        {
            // Новая копия: папки появляются сразу, чтобы было понятно, куда что класть.
            try { Directory.CreateDirectory(Paths.Apps); Directory.CreateDirectory(Paths.Data); CoreLoader.EnsureDir(); }
            catch (Exception ex)
            {
                MessageBox.Show("WinUp не может создать папки рядом с собой:\n" + Paths.Root + "\n\n" + ex.Message +
                                "\n\nПереместите WinUp туда, где можно писать файлы (например, на рабочий стол или флешку).",
                                "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            // WinUp.exe --install id1,id2 [--manual] --apps-sha256 <хэш> — режим установки (с правами администратора).
            // Хэш списка передаёт окно WinUp, в котором нажали «Установить»: список, прочитанный здесь, обязан
            // совпасть с ним — иначе подменённый между нажатием и UAC apps.json запустился бы от администратора.
            string expected = null;
            if (installIdx >= 0)
            {
                int h = Array.IndexOf(args, "--apps-sha256");
                expected = h >= 0 && h + 1 < args.Length ? args[h + 1] : null;
                if (expected == null)
                {
                    MessageBox.Show("Установка с правами администратора запускается только кнопкой «Установить отмеченные» в окне WinUp.",
                        "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            AppStore store;
            string before = installIdx >= 0 ? Integrity.AppsHash() : null;
            // В режиме установки база только читается: список правит основной экземпляр.
            try { store = AppStore.Load(installIdx >= 0); }
            catch (Exception ex)
            {
                MessageBox.Show("Не удалось прочитать " + Paths.AppsFile + ":\n" + ex.Message, "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (installIdx >= 0 && (!string.Equals(before, expected, StringComparison.OrdinalIgnoreCase) ||
                                    !string.Equals(Integrity.AppsHash(), expected, StringComparison.OrdinalIgnoreCase)))
            {
                MessageBox.Show("Список программ (apps.json) изменился после нажатия «Установить» — не через WinUp.\n" +
                    "Установка с правами администратора отменена.", "WinUp", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Некорректный --install (без списка id) отсеян в Main — здесь список гарантированно есть.
            if (installIdx >= 0)
            {
                var ids = args[installIdx + 1].Split(',');
                var items = ids.Select(id => store.Apps.FirstOrDefault(a => a.Id == id)).Where(a => a != null).ToList();
                Application.Run(new InstallForm(items, !args.Contains("--manual")));
                return;
            }
            Application.Run(new MainForm(store));
        }

        // Идентификатор мьютекса зависит от папки: WinUp из разных папок — это разные базы, они могут работать параллельно.
        // Тот же принцип у канала моста расширения (BrowserPipe): браузер каждой папке WinUp шлёт запросы отдельно.
        internal static string FolderHash(string path)
        {
            using (var sha = SHA256.Create())
                return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(path.ToUpperInvariant())))
                    .Replace("/", "_").Replace("+", "-").TrimEnd('=');
        }
    }
}
