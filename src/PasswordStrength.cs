using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace WinUp
{
    // Пароль-фраза из словаря PassphraseWords: слова выбираются криптостойким генератором равномерно.
    static class Passphrase
    {
        public static readonly string[] Words = PassphraseWords.All.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        static readonly HashSet<string> WordSet = new HashSet<string>(Words);

        public static double BitsPerWord { get { return Math.Log(Words.Length, 2); } }

        // Точная стойкость фразы: words·log2(словаря) + цифра в случайном месте.
        public static double Bits(int words, bool digit) { return words * BitsPerWord + (digit ? Math.Log(10 * words, 2) : 0); }

        public static string Make(int words, string separator, bool capitalize, bool digit)
        {
            var parts = new string[words];
            using (var rng = RandomNumberGenerator.Create())
            {
                for (int i = 0; i < words; i++)
                {
                    var w = Words[PasswordGen.Next(rng, Words.Length)];
                    parts[i] = capitalize ? char.ToUpperInvariant(w[0]) + w.Substring(1) : w;
                }
                if (digit) { int at = PasswordGen.Next(rng, words); parts[at] += PasswordGen.Next(rng, 10).ToString(); }
            }
            return string.Join(separator, parts);
        }

        // Фраза из этого словаря: части через один разделитель, каждая — слово (с заглавной буквы или цифрой на конце).
        // Возвращает число слов и есть ли цифра; 0 — не фраза.
        public static int Detect(string pw, out bool digit)
        {
            digit = false;
            if (string.IsNullOrEmpty(pw)) return 0;
            foreach (var sep in new[] { '-', ' ', '.', '_' })
            {
                var parts = pw.Split(sep);
                if (parts.Length < 3) continue;
                bool ok = true, dg = false;
                foreach (var p in parts)
                {
                    var w = p.ToLowerInvariant();
                    if (w.Length > 1 && char.IsDigit(w[w.Length - 1])) { if (dg) { ok = false; break; } dg = true; w = w.Substring(0, w.Length - 1); }
                    if (!WordSet.Contains(w)) { ok = false; break; }
                }
                if (ok) { digit = dg; return parts.Length; }
            }
            return 0;
        }
    }

    // Оценка стойкости пароля в битах — консервативная: повторы, последовательности (abc, 123, qwerty, йцукен),
    // годы и частые пароли почти не добавляют стойкости, фраза из словаря WinUp считается по словам, а не по буквам.
    static class Strength
    {
        public const double MinForVault = 45; // пароль базы слабее — не принимается

        static readonly string[] Common =
        {
            "password", "passw0rd", "qwerty", "qwertz", "azerty", "123456", "654321", "111111", "000000", "123123", "abc123",
            "admin", "letmein", "welcome", "iloveyou", "monkey", "dragon", "master", "sunshine", "princess", "football",
            "parol", "privet", "lubov", "lyubov", "solnyshko", "zaichik", "qazwsx", "1q2w3e", "zxcvbn", "asdfgh",
            "пароль", "привет", "любовь", "солнышко", "йцукен", "фыва", "ячсмит", "qwer", "asdf", "zxcv"
        };
        static readonly string[] Rows = { "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю", "abcdefghijklmnopqrstuvwxyz", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя" };

        public static double Bits(string pw)
        {
            if (string.IsNullOrEmpty(pw)) return 0;
            bool digit;
            int words = Passphrase.Detect(pw, out digit);
            if (words > 0) return Passphrase.Bits(words, digit);

            int pool = 0;
            if (pw.Any(c => c >= 'a' && c <= 'z')) pool += 26;
            if (pw.Any(c => c >= 'A' && c <= 'Z')) pool += 26;
            if (pw.Any(char.IsDigit)) pool += 10;
            if (pw.Any(c => (c >= 'а' && c <= 'я') || c == 'ё')) pool += 33;
            if (pw.Any(c => (c >= 'А' && c <= 'Я') || c == 'Ё')) pool += 33;
            if (pw.Any(c => !char.IsLetterOrDigit(c))) pool += 33;
            if (pw.Any(c => char.IsLetter(c) && c > 'я')) pool += 50;
            double perChar = Math.Log(Math.Max(pool, 2), 2);

            // Частые пароли и раскладочные ряды внутри пароля: такой кусок стоит как одно «слово» (~10 бит).
            var lower = pw.ToLowerInvariant();
            var weak = new bool[pw.Length];
            int fragments = 0;
            foreach (var c in Common)
                for (int i = lower.IndexOf(c, StringComparison.Ordinal); i >= 0; i = lower.IndexOf(c, i + 1, StringComparison.Ordinal))
                {
                    for (int k = i; k < i + c.Length; k++) weak[k] = true;
                    fragments++;
                }
            // Годы 1900–2099: ~7 бит.
            for (int i = 0; i + 4 <= pw.Length; i++)
            {
                var y = pw.Substring(i, 4);
                int n;
                if ((y.StartsWith("19") || y.StartsWith("20")) && int.TryParse(y, out n) && !weak[i]) { for (int k = i; k < i + 4; k++) weak[k] = true; fragments++; }
            }

            double bits = fragments * 10;
            var cost = new double[pw.Length];
            for (int i = 0; i < pw.Length; i++)
            {
                if (weak[i]) continue;
                double w = 1;
                if (i > 0 && lower[i] == lower[i - 1]) w = 0.15;                          // повтор: aaaa
                else if (i > 0 && Sequential(lower[i - 1], lower[i])) w = 0.25;           // ряд: abcd, 1234, qwer, 4321
                else if (!char.IsLetterOrDigit(pw[i]) && pw.IndexOf(pw[i]) < i) w = 0.15;   // тот же разделитель ещё раз
                cost[i] = w * perChar;
            }
            // Длинная череда букв может быть словом из словаря (Moscow, horse, monkey): не дороже ~12 бит за 5 букв
            // и 2 бита за каждую следующую. Случайные буквы так недооцениваются — для пароля базы это безопасная сторона.
            for (int i = 0; i < pw.Length; )
            {
                int j = i;
                while (j < pw.Length && char.IsLetter(pw[j]) && !weak[j]) j++;
                int run = j - i;
                if (run >= 5)
                {
                    double raw = 0;
                    for (int k = i; k < j; k++) raw += cost[k];
                    double cap = 12 + 2 * (run - 5);
                    if (raw > cap) { for (int k = i; k < j; k++) cost[k] = 0; cost[i] = cap; }
                }
                i = j > i ? j : i + 1;
            }
            foreach (var c in cost) bits += c;
            return Math.Min(bits, 128);
        }

        static bool Sequential(char a, char b)
        {
            foreach (var r in Rows)
            {
                int i = r.IndexOf(a), j = r.IndexOf(b);
                if (i >= 0 && j >= 0 && Math.Abs(i - j) == 1) return true;
            }
            return false;
        }

        public static string Verdict(double bits, out Color color)
        {
            if (bits < 28) { color = Color.Firebrick; return "очень слабый"; }
            if (bits < MinForVault) { color = Color.Firebrick; return "слабый"; }
            if (bits < 60) { color = Color.DarkOrange; return "средний"; }
            if (bits < 80) { color = Color.ForestGreen; return "надёжный"; }
            color = Color.ForestGreen; return "очень надёжный";
        }

        public static string Describe(string pw, out Color color)
        {
            if (string.IsNullOrEmpty(pw)) { color = SystemColors.GrayText; return "Надёжность: —"; }
            var bits = Bits(pw);
            var t = "Надёжность: " + Verdict(bits, out color) + " (≈ " + Math.Round(bits) + " бит)";
            if (pw.Any(c => (c >= 'а' && c <= 'я') || (c >= 'А' && c <= 'Я') || c == 'ё' || c == 'Ё'))
                t += ". В пароле русские буквы — при английской раскладке он не введётся";
            return t;
        }
    }

    // Подсказка под полем пароля: текущая раскладка и Caps Lock. Ошибка раскладки в пароле базы стоит попытки.
    sealed class KeyboardHint : Label
    {
        readonly Timer timer = new Timer { Interval = 300 };

        public KeyboardHint()
        {
            AutoSize = true;
            Margin = new Padding(3, 0, 3, 4);
            timer.Tick += (s, e) => Refresh2();
            Refresh2();
            timer.Start();
        }

        void Refresh2()
        {
            string lang;
            try { lang = InputLanguage.CurrentInputLanguage.Culture.TwoLetterISOLanguageName.ToUpperInvariant(); }
            catch { lang = "?"; }
            bool caps = IsKeyLocked(Keys.CapsLock);
            var t = "Раскладка: " + lang + (caps ? " · ВКЛЮЧЁН CAPS LOCK" : "");
            if (Text != t) Text = t;
            ForeColor = caps ? Color.Firebrick : SystemColors.GrayText;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) timer.Dispose();
            base.Dispose(disposing);
        }
    }
}
