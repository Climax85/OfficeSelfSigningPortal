using System.Security.Cryptography.X509Certificates;
using MassTransit;
using MassTransit.Testing;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.SigningService.Data;
using OfficeSelfSigningPortal.SigningService.Messaging;
using OfficeSelfSigningPortal.SigningService.Signing;
using Ossp.Audit;
using Ossp.Contracts;
using OfficeSelfSigningPortal.TestSupport;

namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// Signier-Pipeline hinter dem Guard (TC-27/TC-29, AK-52): Happy Path erzeugt
/// SignMacroCompleted mit neuer SignedArtifactId und Signier-Evidenz im Audit-Trail;
/// abweichender ContentSha256 (TOCTOU) bricht mit SignMacroFailed(Retryable: false) ab
/// (keine Signatur, kein Blob, protokollierter Vorfall); falscher Saga-Status wird
/// übersprungen (Ablehnung bleibt dem Guard vorbehalten); Signatur-Fehler sind nicht
/// retryable; fehlender Blob ist retryable.
/// </summary>
public sealed class SignMacroSigningConsumerTests : IAsyncLifetime
{
    private ServiceProvider _provider = null!;
    private ITestHarness _harness = null!;
    private FakeSagaStateReader _stateReader = null!;
    private FakeArtifactBlobAccess _blobAccess = null!;
    private FakeAuditTrailWriter _auditTrail = null!;
    private FakeKeyProvider _keyProvider = null!;
    private FakeSigner _signer = null!;

    public async Task InitializeAsync()
    {
        _stateReader = new FakeSagaStateReader { State = SagaStateNames.SignierungAngefragt };
        _blobAccess = new FakeArtifactBlobAccess();
        _auditTrail = new FakeAuditTrailWriter();
        _keyProvider = new FakeKeyProvider();
        _signer = new FakeSigner();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISagaStateReader>(_stateReader);
        services.AddSingleton<IArtifactBlobAccess>(_blobAccess);
        services.AddSingleton<IAuditTrailWriter>(_auditTrail);
        services.AddSingleton<ICodeSigningKeyProvider>(_keyProvider);
        services.AddSingleton<IVbaProjectSigner>(_signer);
        services.AddMassTransitTestHarness(x =>
        {
            x.AddSigningGuard();
            x.UsingInMemory((context, cfg) =>
            {
                cfg.ReceiveEndpoint(QueueNames.SignMacroRequested, e =>
                    SigningGuardBusConfiguration.ConfigureSigningGuardEndpoint(
                        e, context, retryLimit: 2, minDelay: TimeSpan.FromMilliseconds(20), maxDelay: TimeSpan.FromMilliseconds(60)));
            });
        });

        _provider = services.BuildServiceProvider(true);
        _harness = _provider.GetRequiredService<ITestHarness>();
        await _harness.Start();
    }

    public async Task DisposeAsync()
    {
        await _harness.Stop();
        await _provider.DisposeAsync();
    }

    [Fact]
    public async Task Clean_Vorgang_durchläuft_Auto_Signing_und_erzeugt_SignedArtifact()
    {
        // Arrange: Auto-Signing-Auftrag über system:auto-sign (TC-27, REQ-13)
        var jobId = Guid.NewGuid();
        var blob = SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject());
        var blobSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(blob));
        var artifactId = Guid.NewGuid();
        _blobAccess.Blobs[artifactId] = new ArtifactBlobContent(blob, blobSha256);
        var request = CreateRequest(jobId, artifactId, blobSha256);

        // Act
        await _harness.Bus.Publish(request);

        // Assert: SignMacroCompleted mit neuer SignedArtifactId, signierter Blob abgelegt
        Assert.True(await _harness.Published.Any<SignMacroCompleted>(m => m.Context.Message.JobId == jobId));
        var completed = _harness.Published.Select<SignMacroCompleted>()
            .Single(m => m.Context.Message.JobId == jobId).Context.Message;
        Assert.True(_blobAccess.Stored.ContainsKey(completed.SignedArtifactId));
        Assert.False(await _harness.Published.Any<SignMacroFailed>(m => m.Context.Message.JobId == jobId));
        Assert.False(await _harness.Published.Any<JobFailed>(m => m.Context.Message.JobId == jobId));

        // Assert: Signier-Evidenz im Audit-Trail (TM-08: Auto-Signing nachvollziehbar)
        var evidence = Assert.Single(_auditTrail.Recorded, e => e.JobId == jobId);
        Assert.Equal(AuditCategories.Signing, evidence.Category);
        Assert.Contains("system:auto-sign", evidence.Detail, StringComparison.Ordinal);
        Assert.True(_keyProvider.WasInvoked); // Zertifikat wurde materialisiert (und vom Consumer disposed)

        // Assert: Pipeline-Signatur ist eine echte V3-Signatur (Roundtrip-Verifikation)
        var signed = _blobAccess.Stored[completed.SignedArtifactId];
        Assert.True(signed.AsSpan().IndexOf("vbaProjectSignatureV3"u8) >= 0);
    }

    [Fact]
    public async Task Abweichender_ContentSha256_bricht_ab_ohne_Signatur_mit_Alarm()
    {
        // Arrange: Blob nach dem Scan getauscht (TOCTOU, AK-52, TC-29)
        var jobId = Guid.NewGuid();
        var blob = SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject());
        var artifactId = Guid.NewGuid();
        _blobAccess.Blobs[artifactId] = new ArtifactBlobContent(blob, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(blob)));
        var tamperedRequestHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("getauschter blob"u8));
        var request = CreateRequest(jobId, artifactId, tamperedRequestHash);

        // Act
        await _harness.Bus.Publish(request);

        // Assert: nicht retryable, keine Signatur, kein Blob, protokollierter Vorfall
        Assert.True(await _harness.Published.Any<SignMacroFailed>(m =>
            m.Context.Message.JobId == jobId && !m.Context.Message.Retryable));
        Assert.False(await _harness.Published.Any<SignMacroCompleted>(m => m.Context.Message.JobId == jobId));
        Assert.Empty(_blobAccess.Stored);
        Assert.False(_signer.WasInvoked);
        Assert.False(_keyProvider.WasInvoked); // Key wird bei TOCTOU gar nicht erst materialisiert

        var incident = Assert.Single(_auditTrail.Recorded, e => e.JobId == jobId);
        Assert.Equal(AuditCategories.Guard, incident.Category);
        Assert.Contains("TOCTOU", incident.Ereignis, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Falscher_Saga_Status_wird_von_der_Pipeline_uebersprungen()
    {
        // Arrange: Vorgang nicht in SignierungAngefragt — der Guard lehnt ab (AK-39),
        // die Pipeline darf nicht zusätzlich signieren oder fehlschlagen.
        var jobId = Guid.NewGuid();
        _stateReader.State = SagaStateNames.ScanLaeuft;
        var blob = SignCorpus.CreateOoxmlMacroFile(SignCorpus.BuildVbaProject());
        var artifactId = Guid.NewGuid();
        var blobSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(blob));
        _blobAccess.Blobs[artifactId] = new ArtifactBlobContent(blob, blobSha256);

        // Act
        await _harness.Bus.Publish(CreateRequest(jobId, artifactId, blobSha256));

        // Assert: Guard-Ablehnung (JobFailed) vorhanden, Pipeline ohne Aktivität
        Assert.True(await _harness.Published.Any<JobFailed>(m => m.Context.Message.JobId == jobId));
        await Task.Delay(TimeSpan.FromMilliseconds(300));
        Assert.False(await _harness.Published.Any<SignMacroCompleted>(m => m.Context.Message.JobId == jobId));
        Assert.False(await _harness.Published.Any<SignMacroFailed>(m => m.Context.Message.JobId == jobId));
        Assert.False(_signer.WasInvoked);
        Assert.Empty(_blobAccess.Stored);
    }

    [Fact]
    public async Task Signatur_Fehler_ist_nicht_retryable()
    {
        // Arrange: VBA-Projekt nicht Office-konform (Signer lehnt fachlich ab)
        var jobId = Guid.NewGuid();
        _signer.Result = new SignResult(false, "vba-project-invalid");
        var blob = System.Text.Encoding.ASCII.GetBytes("kein ooxml");
        var artifactId = Guid.NewGuid();
        var blobSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(blob));
        _blobAccess.Blobs[artifactId] = new ArtifactBlobContent(blob, blobSha256);

        // Act
        await _harness.Bus.Publish(CreateRequest(jobId, artifactId, blobSha256));

        // Assert
        Assert.True(await _harness.Published.Any<SignMacroFailed>(m =>
            m.Context.Message.JobId == jobId && !m.Context.Message.Retryable));
        Assert.False(await _harness.Published.Any<SignMacroCompleted>(m => m.Context.Message.JobId == jobId));
        Assert.Empty(_blobAccess.Stored);
    }

    [Fact]
    public async Task Fehlender_Blob_ist_retryable_und_wird_gepuffert()
    {
        // Arrange: Blob nicht (mehr) lesbar — transiente Inkonsistenz
        var jobId = Guid.NewGuid();
        var request = CreateRequest(jobId, Guid.NewGuid(), Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("x"u8)));

        // Act
        await _harness.Bus.Publish(request);

        // Assert: retryable Fehlermeldung an die Saga; die Exception der Pipeline löst
        // zusätzlich die MassTransit-Redelivery aus (Puffer, kein Request-Verlust).
        Assert.True(await _harness.Published.Any<SignMacroFailed>(m =>
            m.Context.Message.JobId == jobId && m.Context.Message.Retryable));
        Assert.False(await _harness.Published.Any<SignMacroCompleted>(m => m.Context.Message.JobId == jobId));
    }

    private static SignMacroRequested CreateRequest(Guid jobId, Guid artifactId, string contentSha256) => new(
        JobId: jobId,
        ArtifactId: artifactId,
        ContentSha256: contentSha256,
        OriginalFileName: "doku.xlsm",
        ContentType: "xlsm",
        RequestedBy: "system:auto-sign",
        RequestedAt: DateTimeOffset.UtcNow);

    private sealed class FakeAuditTrailWriter : IAuditTrailWriter
    {
        public List<(Guid JobId, string Category, string Ereignis, string Aktor, string? Detail)> Recorded { get; } = [];

        public Task AppendAsync(Guid jobId, string category, string ereignis, string aktor, string? detail, CancellationToken cancellationToken)
        {
            Recorded.Add((jobId, category, ereignis, aktor, detail));
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSagaStateReader : ISagaStateReader
    {
        public string? State { get; set; }

        public Task<string?> GetSagaStateAsync(Guid jobId, CancellationToken cancellationToken) => Task.FromResult(State);
    }

    private sealed class FakeArtifactBlobAccess : IArtifactBlobAccess
    {
        public Dictionary<Guid, ArtifactBlobContent> Blobs { get; } = [];

        public Dictionary<Guid, byte[]> Stored { get; } = [];

        public Task<ArtifactBlobContent?> ReadAsync(Guid artifactId, CancellationToken cancellationToken)
            => Task.FromResult(Blobs.TryGetValue(artifactId, out var blob) ? blob : null);

        public Task<string> StoreSignedAsync(Guid artifactId, byte[] content, CancellationToken cancellationToken)
        {
            Stored[artifactId] = content;
            return Task.FromResult(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)));
        }
    }

    private sealed class FakeKeyProvider : ICodeSigningKeyProvider
    {
        public bool WasInvoked { get; private set; }

        public Task<X509Certificate2> GetSigningCertificateAsync(CancellationToken ct)
        {
            WasInvoked = true;
            return Task.FromResult(VbaProjectSignerTests.CreateCodeSigningCertificate());
        }
    }

    private sealed class FakeSigner : IVbaProjectSigner
    {
        public SignResult Result { get; set; } = new(true, null);

        public bool WasInvoked { get; private set; }

        public async Task<SignResult> SignAsync(Stream document, X509Certificate2 certificate, CancellationToken ct)
        {
            WasInvoked = true;
            await Task.Yield();

            if (!Result.Success)
            {
                return Result;
            }

            // Signierten Inhalt simulieren: echte Signatur + Markierung für die Verifikation
            var signed = new MemoryStream();
            await document.CopyToAsync(signed, ct);
            signed.Write("vbaProjectSignatureV3"u8);
            document.SetLength(0);
            signed.Position = 0;
            await signed.CopyToAsync(document, ct);
            return Result;
        }
    }
}
