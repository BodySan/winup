// Harmless high-version assembly used to demonstrate forged registry trust.
using System.Reflection;
[assembly: AssemblyVersion("99.0.0.0")]
namespace KeePassLib { public static class AuditCanary { public const string Marker = "SYNTHETIC-AUDIT-ONLY"; } }
