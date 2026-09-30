namespace PhishingAnalyser.Tests;

/// <summary>
/// Tests in this collection never run at the same time: the 16-thread classification test saturates the thread pool,
/// which delays the timer behind the reputation lookup timeout (a 200 ms timeout once took 10 s under that load).
/// </summary>
[CollectionDefinition(Name)]
public sealed class TimingSensitive
{
    public const string Name = "Timing-sensitive";
}
