// Minimal compilation-only dependencies for the actual InstallForm.cs. They
// contain no vault, registry, host data access or installer side effects.
using System.IO;
namespace WinUp {
    public sealed class AppItem {public string Name,File,Args;}
    internal static class Paths {internal static string Full(string value){return Path.GetFullPath(value);}}
    internal static class Win {internal static bool IsAdmin(){return false;}}
}
