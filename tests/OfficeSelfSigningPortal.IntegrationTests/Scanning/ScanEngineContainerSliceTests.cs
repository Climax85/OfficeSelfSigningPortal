using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.TestSupport;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.IntegrationTests.Scanning;

/// <summary>
/// Testcontainers-Slice des Seams S3 (genau ein ClamAV/YARA-Slice gegen den
/// Testkorpus, AK-47): echtes clamd (INSTREAM-Protokoll, eigenes Hash-Signatur-Set)
/// und echtes yara-x gegen den synthetischen CFB-Korpus. Prüft die Verdichtung
/// ClamAV-Fund → Malicious (AK-44/TC-14), YARA-Familien-Floor → Malicious
/// (AK-43/TC-13) und den Clean-Pfad inkl. AMSI-Absent (AK-46/TC-18).
///
/// ClamAV läuft offline mit exakt einer Hash-Signatur (.hdb, MD5:Länge:Name über
/// den Korpus-Bytes) — deterministisch und netzunabhängig. Das Image-Volume
/// /var/lib/clamav wird komplett durch das Signatur-Verzeichnis ersetzt.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ScanEngineContainerSliceTests : IAsyncLifetime
{
    private const string ClamAvImage = "clamav/clamav:1.4.6-debian";

    private string _workDir = "";
    private string _signatureDir = "";
    private IContainer _clamAv = null!;
    private string _clamAvHost = "";
    private ushort _clamAvPort;

    public async Task InitializeAsync()
    {
        // Arrange: Signatur-Verzeichnis — genau eine Hash-Signatur über den Fund-Korpus.
        // Zwei Ebenen unter /tmp (sticky): der Container-Entrypoint läuft als root und
        // chownt das Bind-Mount (/var/lib/clamav) rekursiv auf clamav:clamav — das
        // Host-Verzeichnis gehört danach UID 100. Mit 0777 bleibt der Test-Prozess
        // trotzdem über „other“-Rechte schreib- und aufräumberechtigt, und weil das
        // Root-Arbeitsverzeichnis weiterhin dem Prozess gehört, darf er den gechownten
        // Unterordner davon ablösen (sticky /tmp verlangt Besitz nur für Top-Level).
        _workDir = Path.Combine(Path.GetTempPath(), $"ossp-clamav-{Guid.NewGuid():N}");
        _signatureDir = Path.Combine(_workDir, "db");
        Directory.CreateDirectory(_signatureDir);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(_signatureDir,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
        }

        var fundCorpus = ScanCorpus.BuildVbaProject([ScanCorpus.VerhaltensSource], encryptedDir: false);
        var fundMd5 = Convert.ToHexString(MD5.HashData(fundCorpus)).ToLowerInvariant();
        await File.WriteAllTextAsync(
            Path.Combine(_signatureDir, "ossp-test.hdb"),
            $"{fundMd5}:{fundCorpus.LongLength}:Ossp.TestFund\n");

        _clamAv = new ContainerBuilder(ClamAvImage)
            .WithEnvironment("CLAMAV_NO_FRESHCLAMD", "true") // offline — kein freshclam-Lauf
                                                             // Bind-Mount (kein Resource-Mapping): das Image deklariert /var/lib/clamav
                                                             // als VOLUME — nur eine echte Bind mounted darüber und ersetzt die mitgelieferten
                                                             // Signaturen vollständig durch das deterministische Test-Set.
            .WithBindMount(_signatureDir, "/var/lib/clamav", AccessMode.ReadWrite)
            .WithPortBinding(3310, true)
            .Build();

        await _clamAv.StartAsync();
        _clamAvHost = _clamAv.Hostname;
        _clamAvPort = _clamAv.GetMappedPublicPort(3310);
        await WaitForClamdReadyAsync();
    }

    public async Task DisposeAsync()
    {
        await _clamAv.DisposeAsync();
        Directory.Delete(_workDir, recursive: true);
    }

    [Fact]
    public async Task Run_ClamAvFund_liefertMaliciousMitAvFinding()
    {
        // Arrange (AK-44, TC-14): Fund-Korpus gegen ClamAV + Heuristik.
        var orchestrator = CreateOrchestrator(
            clamAv: true,
            yaraRules: null,
            yaraScores: new ScoringOptions());
        var content = ScanCorpus.BuildVbaProject([ScanCorpus.VerhaltensSource], encryptedDir: false);

        // Act
        var completed = await orchestrator.RunAsync(CreateRequest(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Malicious, completed.Verdict);
        Assert.Contains(completed.Engines, e => e is { Engine: "clamav", State: EngineState.Ok });
        Assert.Contains(completed.Findings, f => f.Source == "clamav" && f.Category == "av");
        Assert.Contains(completed.Engines, e => e is { Engine: "amsi", State: EngineState.Absent });
    }

    [Fact]
    public async Task Run_KuratierteFamilienregel_liefertMaliciousUnabhaengigVomPunktstand()
    {
        // Arrange (AK-43, TC-13): cleanes Makro (Score 10) + Familienregel ("Module1"
        // liegt unkomprimiert im PROJECT-Stream des Korpus) → Floor greift.
        var rulesPath = WriteRules("""
            rule Familie_TestKorpus
            {
                strings:
                    $a = "Module1" ascii
                condition:
                    $a
            }
            """);
        var scoring = new ScoringOptions
        {
            YaraRuleScores = { ["Familie_TestKorpus"] = new YaraRuleScore(Points: 40, IsFamily: true) },
        };
        var orchestrator = CreateOrchestrator(clamAv: false, yaraRules: rulesPath, yaraScores: scoring);
        var content = ScanCorpus.BuildVbaProject([ScanCorpus.CleanSource], encryptedDir: false);

        // Act
        var completed = await orchestrator.RunAsync(CreateRequest(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Malicious, completed.Verdict);
        Assert.Equal(50, completed.Score); // 10 Makro + 40 Familie — ohne Floor nur Suspicious.
        Assert.Contains(completed.Findings, f => f.RuleId == "Familie_TestKorpus" && f.Points == 40);
    }

    [Fact]
    public async Task Run_CleanerKorpusOhneSignaturen_liefertClean()
    {
        // Arrange (TC-10/TC-18): Clean-Korpus, ClamAV ohne Treffer, YARA-Regel greift nie.
        var rulesPath = WriteRules("""
            rule Generisch_Niemals
            {
                strings:
                    $a = "definitiv-nicht-im-testkorpus-4711" ascii
                condition:
                    $a
            }
            """);
        var orchestrator = CreateOrchestrator(clamAv: true, yaraRules: rulesPath, yaraScores: new ScoringOptions());
        var content = ScanCorpus.BuildVbaProject([ScanCorpus.CleanSource], encryptedDir: false);

        // Act
        var completed = await orchestrator.RunAsync(CreateRequest(), content, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Clean, completed.Verdict);
        Assert.Equal(10, completed.Score);
        Assert.Contains(completed.Engines, e => e is { Engine: "clamav", State: EngineState.Ok });
        Assert.Contains(completed.Engines, e => e is { Engine: "yara", State: EngineState.Ok });
        Assert.Contains(completed.Engines, e => e is { Engine: "amsi", State: EngineState.Absent });
    }

    private ScanOrchestrator CreateOrchestrator(bool clamAv, string? yaraRules, ScoringOptions yaraScores)
    {
        var engines = new List<IScanEngine>();
        if (clamAv)
        {
            engines.Add(new ClamAvScanEngine(Options.Create(new ScanEnginesOptions
            {
                ClamAvHost = _clamAvHost,
                ClamAvPort = _clamAvPort,
                ClamAvStageTimeout = TimeSpan.FromSeconds(30),
            })));
        }

        if (yaraRules is not null)
        {
            engines.Add(new YaraScanEngine(
                Options.Create(yaraScores),
                Options.Create(new ScanEnginesOptions { YaraRulesPath = yaraRules })));
        }

        return new ScanOrchestrator(
            new HeuristicScanEngine(Options.Create(yaraScores), new VbaProjectExtractor()),
            engines,
            Options.Create(yaraScores),
            Options.Create(new ScanEnginesOptions()),
            NullLogger<ScanOrchestrator>.Instance);
    }

    private string WriteRules(string rules)
    {
        var path = Path.Combine(_signatureDir, $"rules-{Guid.NewGuid():N}.yar");
        File.WriteAllText(path, rules);
        return path;
    }

    private static ScanRequested CreateRequest() =>
        new(JobId: Guid.NewGuid(), ArtifactId: Guid.NewGuid(), ContentSha256: "x",
            OriginalFileName: "korpus.xlsm", ContentType: "xlsm", FileSizeBytes: 1,
            SubmittedBy: "test", RequestedAt: DateTimeOffset.UtcNow);

    /// <summary>Pollt clamd-PING/PONG — Wait-Strategy unabhängig vom Image-Log-Format.</summary>
    private async Task WaitForClamdReadyAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(_clamAvHost, _clamAvPort, timeout.Token);
                await using var stream = client.GetStream();
                await stream.WriteAsync(Encoding.ASCII.GetBytes("zPING\0"), timeout.Token);
                var buffer = new byte[16];
                var read = await stream.ReadAsync(buffer, timeout.Token);
                if (read > 0 && Encoding.ASCII.GetString(buffer, 0, read).Contains("PONG"))
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                if (ex is OperationCanceledException)
                {
                    throw;
                }

                await Task.Delay(500, timeout.Token);
            }
        }
    }
}
