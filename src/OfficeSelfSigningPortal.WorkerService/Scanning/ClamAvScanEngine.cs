using System.Buffers.Binary;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// ClamAV-Stage (Anhang D, AK-44): übergibt den Datei-Stream per clamd-INSTREAM-Protokoll
/// (Chunks mit 4-Byte-Big-Endian-Länge, "zINSTREAM\0"-Kommando). Ein Fund führt unabhängig
/// vom Punktstand zu <c>Malicious</c> (Verdichtung in <see cref="VerdictPolicy"/>).
/// Host nicht konfiguriert ⇒ Stage <see cref="EngineState.Absent"/>.
///
/// Der Protokoll-Client ist absichtlich eigenimplementiert (statt nClam): minimale
/// Oberfläche, durchgehendes CancellationToken (TM-15) und exakte Timeout-Kontrolle.
/// </summary>
public sealed class ClamAvScanEngine(IOptions<ScanEnginesOptions> options) : IScanEngine
{
    private const string InstreamCommand = "zINSTREAM\0";
    private const int MaxChunkSize = 1024 * 1024; // clamd-Standard-Chunkgröße
    private const string CleanReply = "stream: OK";

    public string EngineName => FindingSources.ClamAv;

    public async Task<EngineRun> ScanAsync(ScanTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var config = options.Value;

        if (string.IsNullOrWhiteSpace(config.ClamAvHost))
        {
            return new EngineRun(EngineName, EngineState.Absent, "ClamAV nicht konfiguriert", []);
        }

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(config.ClamAvHost, config.ClamAvPort, cancellationToken);
            await using var stream = client.GetStream();

            var commandBytes = System.Text.Encoding.ASCII.GetBytes(InstreamCommand);
            await stream.WriteAsync(commandBytes, cancellationToken);

            for (var offset = 0; offset < target.Content.Length; offset += MaxChunkSize)
            {
                var length = Math.Min(MaxChunkSize, target.Content.Length - offset);
                var sizePrefix = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(sizePrefix, length);
                await stream.WriteAsync(sizePrefix, cancellationToken);
                await stream.WriteAsync(target.Content.AsMemory(offset, length), cancellationToken);
            }

            // Terminator: 0-Länge, dann Antwort lesen.
            await stream.WriteAsync(new byte[4], cancellationToken);
            var reply = (await ReadReplyAsync(stream, cancellationToken)).Trim('\0');

            return ParseReply(reply);
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
        {
            return new EngineRun(EngineName, EngineState.Failed, ex.GetType().Name, []);
        }
    }

    private EngineRun ParseReply(string reply)
    {
        if (reply.Equals(CleanReply, StringComparison.OrdinalIgnoreCase))
        {
            return new EngineRun(EngineName, EngineState.Ok, null, []);
        }

        // Antwortformat bei Fund: "stream: <Signature> FOUND"
        const string foundSuffix = " FOUND";
        if (reply.EndsWith(foundSuffix, StringComparison.OrdinalIgnoreCase))
        {
            var signature = reply.Substring(0, reply.Length - foundSuffix.Length);
            var detail = signature.StartsWith("stream: ", StringComparison.OrdinalIgnoreCase)
                ? signature["stream: ".Length..]
                : signature;
            return new EngineRun(
                EngineName,
                EngineState.Ok,
                null,
                [new ScanFinding(
                    Source: FindingSources.ClamAv,
                    Category: FindingCategories.Av,
                    RuleId: $"clamav-{detail}",
                    Points: 0,
                    Detail: detail)]);
        }

        return new EngineRun(EngineName, EngineState.Degraded, $"Unerwartete clamd-Antwort: {reply}", []);
    }

    private static async Task<string> ReadReplyAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > 64 * 1024)
            {
                break; // Antworten sind kurze Statuszeilen — Schutz vor Pipe-Datenstrom.
            }
        }

        return System.Text.Encoding.ASCII.GetString(buffer.ToArray()).Trim();
    }
}
