namespace SubactId.Server.Hosting;

/// <summary>
/// A hosted service that runs one pass per tick of a fixed interval. A pass that throws is
/// logged and the next tick runs as usual. Only host shutdown ends the loop. The first pass runs
/// one interval after start, or at start too when <paramref name="passAtStart"/> is set.
/// </summary>
/// <param name="interval">Time between passes.</param>
/// <param name="clock">The clock the timer runs on.</param>
/// <param name="logger">Where failed passes are reported.</param>
/// <param name="passAtStart">Whether a pass runs at start, before the first tick.</param>
public abstract class PeriodicBackgroundService(TimeSpan interval, TimeProvider clock, ILogger logger, bool passAtStart = false) : BackgroundService
{
    /// <summary>The clock passes read the time from.</summary>
    protected TimeProvider Clock { get; } = clock;

    /// <summary>The service's logger.</summary>
    protected ILogger Logger { get; } = logger;

    /// <summary>The pass's name in log messages, for example "Task expiry sweep".</summary>
    protected abstract string PassName { get; }

    /// <summary>One pass.</summary>
    /// <param name="cancellationToken">Signals host shutdown.</param>
    protected abstract Task RunPassAsync(CancellationToken cancellationToken);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(interval, Clock);
        try
        {
            if (passAtStart)
            {
                await RunGuardedAsync(stoppingToken);
            }

            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await RunGuardedAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown.
        }
    }

    /// <summary>Runs one pass and logs any failure.</summary>
    private async Task RunGuardedAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunPassAsync(stoppingToken);
        }
        catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
        {
            Logger.LogError(exception, "{Pass} failed; it will run again at the next tick.", PassName);
        }
    }
}
