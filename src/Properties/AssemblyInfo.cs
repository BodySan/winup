using System.Reflection;

[assembly: AssemblyTitle("WinUp")]
[assembly: AssemblyProduct("WinUp")]
[assembly: AssemblyDescription("Менеджер паролей и программ")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyVersion("1.15.2")]
[assembly: AssemblyFileVersion("1.15.2")]
// Целевая платформа явно: без атрибута сборка через csc («Собрать.cmd») работает в режиме совместимости с .NET 4.0
// (TLS 1.0 по умолчанию и прочие старые умолчания). SDK-сборке генерацию атрибута отключает WinUp.csproj.
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
