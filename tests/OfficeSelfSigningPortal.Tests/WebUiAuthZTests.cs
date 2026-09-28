using System.Net;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;

namespace OfficeSelfSigningPortal.Tests;

/// <summary>
/// Seam S1: AuthN/AuthZ über HTTP gegen die WebUI mit Test-AuthHandler
/// (Fake-IdP-Claims, AK-34). Deckt AK-32, AK-33 (TC-09) und die Policy-
/// Infrastruktur für AK-09 (TC-25 wird in Ticket 07 am Review-API verdrahtet).
/// </summary>
public sealed class WebUiAuthZTests(PortalWebFactory factory) : IClassFixture<PortalWebFactory>
{
    private HttpClient CreateClientFor(string? user, string? groups)
    {
        var client = factory.CreateClient();
        if (user is not null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        }

        if (groups is not null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        }

        return client;
    }

    [Fact]
    public async Task Get_SubmitterBereich_Anonym_WirdMit401Abgewiesen()
    {
        // Arrange — TC-09/AK-33: kein Nutzer, kein Upload wird angenommen.
        // (Der Upload-Endpunkt selbst kommt mit Ticket 03; die Abweisung
        // anonymer Requests ist hier die verbindliche Infrastruktur.)
        var client = factory.CreateClient();

        // Act
        var response = await client.GetAsync("/__test/authz/submitter");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Get_SubmitterBereich_AuthentifiziertOhneGruppenClaims_WirdMit403Abgewiesen()
    {
        // Arrange — AK-32: ohne IdP-Gruppen-Claims gibt es keine Rolle,
        // auch keine hartkodierte oder default-Rolle.
        var client = CreateClientFor(user: "alice", groups: null);

        // Act
        var response = await client.GetAsync("/__test/authz/submitter");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_SubmitterBereich_AuthentifiziertMitUnbekannterGruppe_WirdMit403Abgewiesen()
    {
        // Arrange — AK-32: nur gemappte IdP-Gruppen erzeugen Rollen.
        var client = CreateClientFor(user: "alice", groups: "FremdeGruppe");

        // Act
        var response = await client.GetAsync("/__test/authz/submitter");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_SubmitterBereich_MitEinreicherGruppenClaim_WirdErreicht()
    {
        // Arrange — AK-34: Fake-IdP liefert Gruppen-Claims in IdP-Form,
        // die Transformation leitet daraus die Rolle ab.
        var client = CreateClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.GetAsync("/__test/authz/submitter");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Get_EditorBereich_NurMitEinreicherClaim_WirdMit403Abgewiesen()
    {
        // Arrange — AK-09 (Policy-Infrastruktur; TC-25 am Review-API folgt in Ticket 07).
        var client = CreateClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.GetAsync("/__test/authz/editor");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_EditorBereich_MitBearbeiterGruppenClaim_WirdErreicht()
    {
        // Arrange
        var client = CreateClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.GetAsync("/__test/authz/editor");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Get_AdminBereich_MitNurBearbeiterClaim_WirdMit403Abgewiesen()
    {
        // Arrange — RV-07: Cross-Roll-Abfrage auch für Bearbeiter → Admin.
        var client = CreateClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.GetAsync("/__test/authz/administrator");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_EditorBereich_MitDirektemRoleClaimAberOhneGruppen_WirdMit403Abgewiesen()
    {
        // Arrange — AK-32/RV-05: ein IdP, der Rollen-Claims direkt liefert
        // (simuliert via X-Test-Roles), darf keine Berechtigung erzeugen —
        // ausschließlich Gruppen-Claims zählen.
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, "mallory");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RolesHeader, "Bearbeiter");

        // Act
        var response = await client.GetAsync("/__test/authz/editor");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_AdminBereich_MitAdminGruppenClaim_WirdErreicht()
    {
        // Arrange
        var client = CreateClientFor(user: "root", groups: "Admin");

        // Act
        var response = await client.GetAsync("/__test/authz/administrator");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
