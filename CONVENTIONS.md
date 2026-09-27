# CONVENTIONS

Verbindliche Konventions-Datei für Reviews (`code-review`, `review-ticket`).

## 1. Stack & Sprache

- C# / .NET (jeweils aktuelles LTS), ASP.NET Core, EF Core, PostgreSQL, .NET Aspire, RabbitMQ über MassTransit.
- Nullable Reference Types und Implicit Usings sind aktiviert (Projekt-Default, nicht abschalten).
- Code-Identifier und API-Routen englisch; Commit-Nachrichten und Doku deutsch.
- Formatierung: `dotnet format`, file-scoped namespaces, 4 Spaces.

## 2. Architektur

- Lösungsstruktur folgt .NET Aspire: AppHost + ServiceDefaults, ein Projekt pro fachlichem Kontext (kein technisches Layer-Schichten-Modell ohne fachlichen Grund).
- Nachrichtenflüsse ausschließlich über MassTransit/RabbitMQ; direkter HTTP zwischen Services nur nach ADR.
- EF Core: ein DbContext pro fachlichem Kontext, Migrations pro Kontext-Datenbank, kein Raw SQL ohne Parameterisierung.
- Konfiguration über Options-Pattern + `appsettings.json`/Aspire-Injection; keine statische Konfiguration.

## 3. Tests

- xUnit; Datenbank- und Broker-Integrationstests mit Testcontainers (PostgreSQL, RabbitMQ) — keine gemockten DbContexts für Verhalten, das EF-Core-Übersetzung betrifft.
- Testnamen: `Methode_Bedingung_ErwartetesVerhalten` (deutsche Beschreibung erlaubt, Struktur Pflicht), AAA-Kommentare (`// Arrange` / `// Act` / `// Assert`).
- Secure-SDLC: jeder `AC-nn` (Abuse-Case) braucht mindestens einen `TC-nn`; Test-Cases aus `test-cases.md` werden vor der Implementierung geschrieben (TDD).

## 4. Commit-Regeln

- Ein Commit = ein Ticket (siehe `docs/agents/issue-tracker.md`); Ticket-Referenz in der Nachricht.
- Imperativ, deutsch, erste Zeile ≤ 72 Zeichen, z. B. `REQ-03: Upload-Validierung auf PDF beschränken`.
- Keine generierten Artefakte (bin/, obj/ nie; EF-Migrations inkl. Snapshots sind erlaubt).

## 5. Verbindliche Patterns

- Durchgängig async (`Async`-Suffix, `CancellationToken` bis in die Leafs).
- Dependency Injection über Konstruktor; kein `new` auf Services, kein Service Locator.
- Validierung am Systemrand (Minimal-API-Filter oder FluentValidation), nie nur im Frontend.
- Secrets nur über Aspire/User-Secrets/Umgebungsvariablen — niemals in Repo oder `appsettings.json` committen.
- Logging über `ILogger` strukturiert, keine String-Interpolation in Log-Templates.

## 6. Security-Baseline

- EF Core parametrisiert standardmäßig; jede Abweichung (Raw SQL, Dynamic LINQ) braucht Kommentar + Review-Freigabe.
- Authentisierung/Autorisierung zentral pro Endpunkt deklariert; kein anonymer Endpunkt ohne Eintrag im Threat Model (`IF-nn`).
- Alle externen Eingaben als untrusted behandeln: Größenlimits, Content-Type-Prüfung, Pfad-Sanitizierung.
