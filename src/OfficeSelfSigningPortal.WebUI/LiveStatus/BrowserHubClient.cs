using Microsoft.JSInterop;

namespace OfficeSelfSigningPortal.WebUI.LiveStatus;

/// <summary>
/// Kapselt den Browser-SignalR-Client für den <see cref="JobStatusHub"/> (IF-03).
///
/// Der Hub verlangt Authentifizierung (FallbackPolicy, TM-17). Ein serverseitig im
/// Circuit gebauter <c>HubConnection</c> sendet keine Browser-Cookies und scheitert
/// am OIDC-Challenge — der Browser-Client dagegen sendet den Auth-Cookie nativ,
/// sodass <c>Context.User</c> im Hub korrekt befüllt ist und die serverseitige
/// Watch-Autorisierung (AK-09) greift.
///
/// Verdrahtung: <see cref="StartAsync"/> importiert wwwroot/js/live-status.js,
/// registriert die Komponente (<paramref name="receiver"/>) samt ihrer
/// [JSInvokable]-Handlermethoden und startet die Verbindung. JS-Interop ist erst
/// ab <c>OnAfterRenderAsync(firstRender: true)</c> zulässig (Prerendering!).
///
/// Authentisierungs-Fenster: Vor dem Login (Negotiate → 302 auf den IdP) wirft
/// <see cref="StartAsync"/> — die aufrufende Komponente fängt das ab; die Seite
/// bleibt ohne Live-Kanal nutzbar.
/// </summary>
public sealed class BrowserHubClient : IAsyncDisposable
{
    private readonly IJSObjectReference _module;
    private readonly DotNetObjectReference<object> _self;
    private readonly int _connectionId;

    private BrowserHubClient(
        IJSObjectReference module, DotNetObjectReference<object> self, int connectionId)
    {
        _module = module;
        _self = self;
        _connectionId = connectionId;
    }

    /// <summary>
    /// Baut die Browser-Verbindung auf und startet sie.
    /// </summary>
    /// <param name="js">JS-Runtime des Circuits.</param>
    /// <param name="hubUrl">Absoluter Hub-Endpunkt.</param>
    /// <param name="receiver">Komponente mit den [JSInvokable]-Handlern.</param>
    /// <param name="handlerMap">Hub-Client-Methode → Name der [JSInvokable]-Methode.</param>
    public static async Task<BrowserHubClient> StartAsync(
        IJSRuntime js,
        Uri hubUrl,
        object receiver,
        IReadOnlyDictionary<string, string> handlerMap,
        CancellationToken cancellationToken = default)
    {
        var module = await js.InvokeAsync<IJSObjectReference>(
            "import", cancellationToken, "./js/live-status.js");
        try
        {
            var self = DotNetObjectReference.Create(receiver);
            var id = await module.InvokeAsync<int>(
                "create", cancellationToken, hubUrl.ToString(), self, handlerMap);
            try
            {
                await module.InvokeAsync<object?>("start", cancellationToken, id);
            }
            catch
            {
                await DisposeModuleConnectionAsync(module, id);
                self.Dispose();
                throw;
            }

            return new BrowserHubClient(module, self, id);
        }
        catch
        {
            await module.DisposeAsync();
            throw;
        }
    }

    /// <summary>Ruft eine Server-Hub-Methode auf (WatchJob/WatchDashboard/WatchNotifications).</summary>
    public Task InvokeAsync(string method, params object?[] args)
    {
        return InvokeAsync(CancellationToken.None, method, args);
    }

    /// <summary>Ruft eine Server-Hub-Methode mit Abbruchunterstützung auf.</summary>
    public async Task InvokeAsync(
        CancellationToken cancellationToken, string method, params object?[] args)
    {
        await _module.InvokeAsync<object?>("invoke", cancellationToken, _connectionId, method, args);
    }

    /// <summary>Stoppt die Verbindung und gibt JS-Referenzen frei.</summary>
    public async ValueTask DisposeAsync()
    {
        try
        {
            await DisposeModuleConnectionAsync(_module, _connectionId);
            _self.Dispose();
            await _module.DisposeAsync();
        }
        catch (JSDisconnectedException)
        {
            // Circuit bereits beendet — JS-Seite existiert nicht mehr.
        }
    }

    private static async Task DisposeModuleConnectionAsync(IJSObjectReference module, int id)
    {
        try
        {
            await module.InvokeAsync<object?>("dispose", id);
        }
        catch (JSDisconnectedException)
        {
            // Circuit bereits beendet — JS-Seite existiert nicht mehr.
        }
    }
}
