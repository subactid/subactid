namespace SubactId.Sample.Agent;

/// <summary>Console output for the demo. Never prints a token, a grant or a key.</summary>
internal static class Narrate
{
    private const int LabelWidth = 20;

    /// <summary>A titled block, for the opening and closing notes.</summary>
    public static void Banner(string title, params string[] lines)
    {
        Console.WriteLine();
        Console.WriteLine($"=== {title} {new string('=', Math.Max(0, 68 - title.Length))}");
        foreach (var line in lines)
        {
            Console.WriteLine(line);
        }
    }

    /// <summary>Starts a numbered step.</summary>
    public static void Step(int number, int of, string title)
    {
        Console.WriteLine();
        Console.WriteLine($"[{number}/{of}] {title}");
    }

    /// <summary>A labelled fact about the step.</summary>
    public static void Detail(string label, string value) =>
        Console.WriteLine($"        {label.PadRight(LabelWidth)} {value}");

    /// <summary>Something the control plane allowed.</summary>
    public static void Allowed(string message) => Console.WriteLine($"    ok  {message}");

    /// <summary>Something the control plane or the tool server refused.</summary>
    public static void Denied(string message) => Console.WriteLine($"  deny  {message}");

    /// <summary>A plain note.</summary>
    public static void Note(string message) => Console.WriteLine($"        {message}");

    /// <summary>The quickstart could not finish.</summary>
    public static void Failed(string message)
    {
        Console.WriteLine();
        Console.Error.WriteLine($"The quickstart stopped: {message}");
    }
}
