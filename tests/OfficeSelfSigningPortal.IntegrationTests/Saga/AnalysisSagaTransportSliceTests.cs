using System.Diagnostics;
using Npgsql;
using OfficeSelfSigningPortal.IntegrationTests.Testcontainers;
using Testcontainers.PostgreSql;
using Testcontainers.RabbitMq;

namespace OfficeSelfSigningPortal.IntegrationTests.Saga;

/// <summary>
/// Transport-Slice des Seams S2 (genau ein RabbitMQ-Testcontainers-Slice, AK-40):
/// Transport-Vertrauen über den InMemory-Harness hinaus, EF-Core-Saga-Persistenz
/// und Outbox auf Testcontainers-PostgreSQL, Fortsetzung über einen Worker-Neustart
/// (TC-39, REQ-11) sowie der SigningService-Guard gegen den echten State-Store
/// (TM-19, AK-39, TC-30).
///
/// Der Szenario-Ablauf läuft im <see cref="OfficeSelfSigningPortal.SagaTransportHarness"/>
/// (eigener Prozess): Die Test-Suite orchestriert ausschließlich Container und
/// wertet dessen Marker/Exitcode aus. Hintergrund: Die MassTransit-Start-/Consume-
/// Pipeline hing in der Testrunner-Prozessumgebung zeitweise permanent (alle Threads
/// idle, async-Kette ohne Fortschritt); als eigener Prozess läuft dasselbe Szenario
/// deterministisch. Die vollständige Zustandslogik bleibt unabhängig davon im
/// InMemory-Seam S2 gedeckt (<c>AnalysisSagaInMemoryTests</c>).
/// </summary>
[Trait("Category", "Integration")]
public sealed class AnalysisSagaTransportSliceTests : IAsyncLifetime
{
    private PostgreSqlContainer _postgres = null!;
    private RabbitMqContainer _rabbitMq = null!;
    private string _workerConnectionString = "";
    private string _signingConnectionString = "";
    private string _rabbitMqConnectionString = "";
    private string _harnessPath = "";

    public async Task InitializeAsync()
    {
        // Arrange
        _postgres = TestContainers.CreatePostgres();
        _rabbitMq = TestContainers.CreateRabbitMq();
        await Task.WhenAll(_postgres.StartAsync(), _rabbitMq.StartAsync());

        // Zwei Datenbanken auf einem Server, damit beide DbContexts sauber migrieren
        // (je eigener __EFMigrationsHistory).
        await _postgres.ExecScriptAsync("CREATE DATABASE signing;");

        _workerConnectionString = _postgres.GetConnectionString();
        _signingConnectionString = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Database = "signing",
        }.ConnectionString;
        _rabbitMqConnectionString =
            $"amqp://ossp:ossp-test@{_rabbitMq.Hostname}:{_rabbitMq.GetMappedPublicPort(5672)}";

        _harnessPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "OfficeSelfSigningPortal.SagaTransportHarness", "bin", GetConfiguration(), "net10.0",
            "OfficeSelfSigningPortal.SagaTransportHarness.dll"));
        Assert.True(File.Exists(_harnessPath), $"Harness-Assembly fehlt: {_harnessPath}");
    }

    public async Task DisposeAsync()
    {
        await Task.WhenAll(_postgres.DisposeAsync().AsTask(), _rabbitMq.DisposeAsync().AsTask());
    }

    [Fact]
    public async Task ScanRequested_über_RabbitMQ_persistiert_und_setzt_sich_nach_WorkerNeustart_fort()
    {
        // Act (AK-40: Transport-Vertrauen; TC-39: Neustart-Fortsetzung; REQ-18: Audit je Übergang)
        var output = await RunHarnessAsync("worker");

        // Assert
        Assert.Contains("MARKER STATE ScanLaeuft", output);
        Assert.Contains("MARKER STATE SignierungAngefragt", output);
        Assert.Contains("MARKER STATE Signiert", output);
        Assert.Contains("MARKER AUDIT-COUNT", output);
        Assert.Contains("MARKER SUCCESS", output);
    }

    [Fact]
    public async Task SignMacroRequested_ohne_SignierungAngefragt_wird_vom_Guard_mit_echtem_StateStore_abgelehnt()
    {
        // Act (TM-19, AK-39, TC-30)
        var output = await RunHarnessAsync("signing", _signingConnectionString);

        // Assert
        Assert.Contains("MARKER GUARD-REJECTED", output);
        Assert.Contains("MARKER INCIDENTS 1", output);
        Assert.Contains("MARKER GUARD-ACCEPTED", output);
        Assert.Contains("MARKER SUCCESS", output);
    }

    private async Task<string> RunHarnessAsync(string modus, string? signingConnectionString = null)
    {
        var arguments = $"\"{_harnessPath}\" \"{_workerConnectionString}\" \"{_rabbitMqConnectionString}\" {modus}";
        if (signingConnectionString is not null)
        {
            arguments += $" \"{signingConnectionString}\"";
        }

        using var process = new System.Diagnostics.Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };

        var stdout = new StringWriter();
        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                stdout.WriteLine(e.Data);
            }
        };

        process.Start();
        process.BeginOutputReadLine();
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(6));
        await process.WaitForExitAsync(cts.Token);
        

        Assert.True(process.ExitCode == 0,
            $"Harness fehlgeschlagen (Exit {process.ExitCode}):{Environment.NewLine}{stdout}");
        return stdout.ToString();
    }

    private static string GetConfiguration()
    {
#if DEBUG
        return "Debug";
#else
        return "Release";
#endif
    }
}
