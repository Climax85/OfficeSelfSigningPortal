// Interop-Modul für den Browser-SignalR-Client des JobStatusHub (IF-03).
//
// Warum JS statt serverseitigem HubConnection: Der Hub verlangt Authentifizierung
// (FallbackPolicy, TM-17). Ein serverseitig im Circuit gebauter HubConnection sendet
// keine Browser-Cookies — der Browser-Client hingegen schickt den Auth-Cookie
// nativ mit (Negotiate und WebSocket), Context.User im Hub ist korrekt befüllt.
//
// Verwaltet je Komponente eine Verbindung; Ereignisse werden als
// DotNetObjectReference-Rückrufe an [JSInvokable]-Methoden der Komponente
// delegiert (Argumente werden als JSON übergeben, STJ deserialisiert sie in die
// DTOs aus LiveStatus/StatusEvents.cs).

const connections = new Map();
let nextId = 0;

/** Baut eine Verbindung auf und verknüpft Hub-Ereignisse mit .NET-Rückrufen. */
export function create(hubUrl, dotNetHelper, handlerMap) {
    const connection = new signalR.HubConnectionBuilder()
        .withUrl(hubUrl)
        .withAutomaticReconnect()
        .build();

    for (const [hubMethod, dotnetMethod] of Object.entries(handlerMap)) {
        connection.on(hubMethod, (...args) => {
            // Jede Hub-Client-Methode versendet genau ein Ereignis-Objekt.
            // Eine throwende .NET-Seite darf keinen unbehandelten Rejection
            // im Browser auslösen — Fehler werden geloggt.
            dotNetHelper.invokeMethodAsync(dotnetMethod, args.length > 0 ? args[0] : null)
                .catch(err => console.error(`live-status: Handler ${dotnetMethod} fehlgeschlagen`, err));
        });
    }

    const id = ++nextId;
    connections.set(id, connection);
    return id;
}

/** Startet die Verbindung. Fehler (z. B. noch nicht authentifiziert → 302 auf den
 *  IdP) werden nach außen gegeben — die aufrufende Komponente fängt sie ab. */
export async function start(id) {
    await connections.get(id).start();
}

/** Ruft eine Server-Hub-Methode auf (WatchJob/WatchDashboard/WatchNotifications).
 *  args: optionales Argument-Array (z. B. [jobId]) — wird gespreadet übergeben. */
export async function invoke(id, method, args) {
    await connections.get(id).invoke(method, ...(args ?? []));
}

/** Beendet die Verbindung und entfernt sie aus der Verwaltung. */
export async function dispose(id) {
    const connection = connections.get(id);
    if (connection) {
        connections.delete(id);
        await connection.stop();
    }
}
