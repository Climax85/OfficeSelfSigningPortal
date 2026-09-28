using System.Net.Http.Headers;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using OfficeSelfSigningPortal.WebUI.Ingestion;

namespace OfficeSelfSigningPortal.Tests.Support;

/// <summary>
/// HTTP-Client für Seam S1: holt das Antiforgery-Token-Paar (Cookie + Header)
/// und reicht Multipart-Uploads mit Fake-IdP-Claims ein.
/// </summary>
public sealed class SubmissionApiClient
{
    public const string AntiforgeryHeader = "RequestVerificationToken";

    private readonly HttpClient _client;
    private string? _antiforgeryToken;

    public SubmissionApiClient(HttpClient client, string user, string groups)
    {
        _client = client;
        _client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        _client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
    }

    public async Task<HttpResponseMessage> PostSubmissionAsync(string fileName, byte[] content)
    {
        await EnsureAntiforgeryTokenAsync();

        using var multipart = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(content);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        multipart.Add(fileContent, "file", fileName);

        _client.DefaultRequestHeaders.Remove(AntiforgeryHeader);
        _client.DefaultRequestHeaders.Add(AntiforgeryHeader, _antiforgeryToken);

        return await _client.PostAsync("/api/submissions", multipart);
    }

    public async Task<HttpResponseMessage> GetStatusRawAsync(Guid jobId)
        => await _client.GetAsync($"/api/submissions/{jobId}");

    public async Task<SubmissionStatusResponse> GetStatusAsync(Guid jobId)
    {
        var response = await GetStatusRawAsync(jobId);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>())!;
    }

    private async Task EnsureAntiforgeryTokenAsync()
    {
        if (_antiforgeryToken is not null)
        {
            return;
        }

        var response = await _client.GetAsync("/api/submissions/upload-token");
        response.EnsureSuccessStatusCode();
        var body = (await response.Content.ReadFromJsonAsync<UploadTokenResponse>())!;
        _antiforgeryToken = body.Token;
    }
}
