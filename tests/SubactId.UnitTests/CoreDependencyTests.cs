using System.Reflection;
using Xunit;

namespace SubactId.UnitTests;

public class CoreDependencyTests
{
    [Fact]
    public void Core_references_nothing_outside_the_base_class_library()
    {
        var core = Assembly.Load(new AssemblyName("SubactId.Core"));

        var external = core.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => !IsBaseClassLibrary(n))
            .ToList();

        Assert.Empty(external);
    }

    private static bool IsBaseClassLibrary(string assemblyName) =>
        assemblyName == "mscorlib"
        || assemblyName == "netstandard"
        || assemblyName.StartsWith("System.", StringComparison.Ordinal)
        || assemblyName == "System";
}
