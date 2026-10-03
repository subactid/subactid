using System.Reflection;
using System.Text.RegularExpressions;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Configuration;

/// <summary>
/// The Helm chart against the settings the server reads. A setting the chart renders under a name
/// the server does not read is ignored without a word, and a setting the chart cannot render
/// cannot be used from it, so both are held here.
/// </summary>
public partial class HelmChartSettingsTests
{
    // The chart supports Postgres only and projects signing keys as files.
    private static readonly string[] LeftOutOnPurpose =
    [
        "Database:Provider",
        "Database:Path",
        "Signing:Keys:N:Pem",
    ];

    [Fact]
    public void Every_setting_the_chart_renders_is_one_the_server_reads()
    {
        var server = ServerSettings();

        Assert.DoesNotContain(ChartSettings(), setting => !server.Contains(setting));
    }

    [Fact]
    public void Every_setting_the_server_reads_has_a_chart_value_except_those_left_out_on_purpose()
    {
        var chart = ChartSettings();

        Assert.DoesNotContain(ServerSettings(), setting => !chart.Contains(setting) && !LeftOutOnPurpose.Contains(setting, StringComparer.OrdinalIgnoreCase));
    }

    private static HashSet<string> ServerSettings()
    {
        // The loader names each setting in a constant ending in "Key", under the SubactId section.
        var settings = typeof(SubactIdOptionsLoader)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.Name.EndsWith("Key", StringComparison.Ordinal))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Signing keys are a numbered section, read entry by entry.
        Assert.True(settings.Remove("Signing:Keys"));
        settings.UnionWith(["Signing:Keys:N:Path", "Signing:Keys:N:Pem", "Signing:Keys:N:Kid"]);
        return settings;
    }

    private static HashSet<string> ChartSettings()
    {
        var settings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(Path.Combine(RepositoryRoot(), "deploy", "helm", "subactid", "templates"), "*", SearchOption.AllDirectories))
        {
            foreach (Match match in EnvironmentName().Matches(File.ReadAllText(file)))
            {
                var key = match.Groups["key"].Value.Replace("__", ":", StringComparison.Ordinal);
                settings.Add(TemplateAction().Replace(key, "N"));
            }
        }

        Assert.NotEmpty(settings);
        return settings;
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "deploy", "helm", "subactid", "Chart.yaml")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The Helm chart is not above the test's directory. These tests run from a checkout of the repository.");
    }

    // SubactId__Section__Key, where a segment may be a template action such as {{ $index }}.
    [GeneratedRegex(@"SubactId__(?<key>[A-Za-z0-9]+(?:__(?:[A-Za-z0-9]+|\{\{[^}]*\}\}))*)", RegexOptions.CultureInvariant)]
    private static partial Regex EnvironmentName();

    [GeneratedRegex(@"\{\{[^}]*\}\}", RegexOptions.CultureInvariant)]
    private static partial Regex TemplateAction();
}
