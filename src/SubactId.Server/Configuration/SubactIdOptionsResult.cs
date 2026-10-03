namespace SubactId.Server.Configuration;

/// <summary>Outcome of <see cref="SubactIdOptionsLoader.Load"/>: either validated options or a list of errors.</summary>
public sealed class SubactIdOptionsResult
{
    private SubactIdOptionsResult(SubactIdOptions? options, IReadOnlyList<string> errors)
    {
        Options = options;
        Errors = errors;
    }

    /// <summary>The validated options. Only set when <see cref="IsValid"/> is <c>true</c>.</summary>
    public SubactIdOptions? Options { get; }

    /// <summary>Every validation problem found, each naming the offending key. Empty when valid.</summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary><c>true</c> when configuration is complete and consistent.</summary>
    public bool IsValid => Options is not null;

    internal static SubactIdOptionsResult Valid(SubactIdOptions options) => new(options, []);

    internal static SubactIdOptionsResult Invalid(IReadOnlyList<string> errors) => new(null, errors);
}
