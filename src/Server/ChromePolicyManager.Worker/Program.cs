using Azure.Identity;
using ChromePolicyManager.Worker.Services;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Graph;

var builder = FunctionsApplication.CreateBuilder(args);

// Microsoft Graph client (Managed Identity in Azure, az-cli/VS credentials locally).
builder.Services.AddSingleton(_ =>
{
    var credential = new DefaultAzureCredential();
    return new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
});

// Privileged Graph actions (push remediation) + status publisher (cpm-command-status).
builder.Services.AddSingleton<StatusPublisher>();
builder.Services.AddScoped<PrivilegedGraphActions>();

builder.Build().Run();
