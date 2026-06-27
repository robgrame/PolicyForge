using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using Microsoft.Graph;
using Azure.Identity;
using Azure.Data.AppConfiguration;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Services;
using ChromePolicyManager.Api.Endpoints;
using ChromePolicyManager.Api.Middleware;
using ChromePolicyManager.Api.Hubs;


var builder = WebApplication.CreateBuilder(args);

// Azure App Configuration is the single source of truth for app/portal settings.
// Load it as a configuration provider FIRST so every subsequent Configuration read
// (connection string, AzureAd, Hubs:RequireAuth, EventGrid, ...) resolves from App Config,
// with appsettings.json only providing local defaults. Uses Managed Identity in Azure.
var appConfigEndpoint = builder.Configuration["AppConfig:Endpoint"];
if (!string.IsNullOrWhiteSpace(appConfigEndpoint))
{
    builder.Configuration.AddAzureAppConfiguration(options =>
        options.Connect(new Uri(appConfigEndpoint), new DefaultAzureCredential()));
}

// Application Insights via OpenTelemetry
builder.Services.AddOpenTelemetry().UseAzureMonitor();

// Database - SQL Server when connection string is configured, SQLite as fallback for local dev
var sqlConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (!string.IsNullOrEmpty(sqlConnectionString))
{
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlServer(sqlConnectionString));
}
else
{
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlite("Data Source=chromepolicymanager.db"));
}

// Microsoft Identity / Auth — accept both v1 and v2 tokens from MI and interactive flows
var tenantId = builder.Configuration["AzureAd:TenantId"];
var clientId = builder.Configuration["AzureAd:ClientId"];
builder.Services.AddMicrosoftIdentityWebApiAuthentication(builder.Configuration, "AzureAd");
// PostConfigure runs AFTER Microsoft.Identity.Web's PostConfigure, ensuring our overrides stick
builder.Services.PostConfigure<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>(
    Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme,
    options =>
    {
        // Accept both v1 and v2 issuers (MI tokens may use either)
        options.TokenValidationParameters.ValidIssuers = new[]
        {
            $"https://sts.windows.net/{tenantId}/",
            $"https://login.microsoftonline.com/{tenantId}/v2.0"
        };
        // Accept both audience formats: v2 tokens use bare clientId, v1 use Application ID URI
        options.TokenValidationParameters.ValidAudiences = new[]
        {
            clientId,
            $"api://{clientId}"
        };

        // SignalR clients cannot set the Authorization header on the WebSocket handshake,
        // so they pass the bearer token via the access_token query string. Pull it from
        // there for hub paths so [Authorize] hubs can validate the token.
        var originalOnMessageReceived = options.Events?.OnMessageReceived;
        options.Events ??= new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents();
        options.Events.OnMessageReceived = async context =>
        {
            if (originalOnMessageReceived is not null)
            {
                await originalOnMessageReceived(context);
            }

            var accessToken = context.Request.Query["access_token"];
            var path = context.HttpContext.Request.Path;
            if (!string.IsNullOrEmpty(accessToken) &&
                (path.StartsWithSegments(PolicyStatusHub.Path) ||
                 path.StartsWithSegments(CommandStatusHub.Path)))
            {
                context.Token = accessToken;
            }
        };
    });

// Microsoft Graph client (uses Managed Identity in Azure, falls back to CLI locally)
builder.Services.AddSingleton(sp =>
{
    var credential = new DefaultAzureCredential();
    return new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
});

// Application services
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<PolicyService>();
builder.Services.AddScoped<AssignmentService>();
builder.Services.AddScoped<PushRemediationService>();
builder.Services.AddScoped<EffectivePolicyService>();
builder.Services.AddScoped<DeviceReportingService>();
builder.Services.AddScoped<IGraphService, GraphService>();
builder.Services.AddSingleton<ChromePolicyValidator>();
builder.Services.AddSingleton<AdmxParserService>();
builder.Services.AddHttpClient(); // For ADMX download from Google

// Azure App Configuration client for ClientCert:* trust settings (Managed Identity).
// Reuses the endpoint resolved above; only registered when configured.
if (!string.IsNullOrWhiteSpace(appConfigEndpoint))
{
    builder.Services.AddSingleton(new ConfigurationClient(new Uri(appConfigEndpoint), new DefaultAzureCredential()));
}
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<IClientCertConfigStore>(sp =>
    new AppConfigClientCertConfigStore(
        sp.GetRequiredService<ILogger<AppConfigClientCertConfigStore>>(),
        sp.GetService<ConfigurationClient>()));

// Service Bus - async device report processing
builder.Services.AddSingleton<DeviceReportQueue>();
builder.Services.AddHostedService<DeviceReportProcessor>();

// Decoupled privileged-action pipeline (ADR-001): command publisher + status relay + SignalR.
builder.Services.AddSingleton<CommandQueueClient>();
builder.Services.AddScoped<ICommandPublisher, CommandPublisher>();
builder.Services.AddSignalR();
builder.Services.AddHostedService<CommandStatusRelay>();

// Event Grid status pipeline: publish device policy-application status for portal fan-out.
builder.Services.AddSingleton<IEventPublisher, EventGridEventPublisher>();

// Graph change notifications - webhook subscription management
builder.Services.AddHostedService<GroupChangeNotificationService>();

// OpenAPI / Swagger
builder.Services.AddOpenApi();

// JSON serialization - handle EF Core circular references
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

// CORS for management UI
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowManagementUI", policy =>
        policy.WithOrigins(builder.Configuration.GetSection("Cors:Origins").Get<string[]>() ?? Array.Empty<string>())
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()); // required for SignalR (CommandStatusHub)
});

// Increase request size limit for ADMX zip upload
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 200 * 1024 * 1024; // 200MB
});

var app = builder.Build();

// Auto-migrate database schema additions
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (app.Environment.IsDevelopment())
    {
        db.Database.EnsureCreated();
    }
    // Add columns that may not exist yet (idempotent)
    try
    {
        await db.Database.ExecuteSqlRawAsync(@"
            IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('DeviceStates') AND name = 'ScriptVersion')
                ALTER TABLE DeviceStates ADD ScriptVersion NVARCHAR(50) NULL;
            IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('DeviceReports') AND name = 'ScriptVersion')
                ALTER TABLE DeviceReports ADD ScriptVersion NVARCHAR(50) NULL;

            IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('PolicySetVersions') AND name = 'AdmxVersion')
                ALTER TABLE PolicySetVersions ADD AdmxVersion NVARCHAR(50) NULL;

            IF OBJECT_ID('PrivilegedCommands', 'U') IS NULL
            CREATE TABLE PrivilegedCommands (
                Id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
                Type INT NOT NULL,
                Status INT NOT NULL,
                PayloadJson NVARCHAR(2000) NULL,
                Actor NVARCHAR(256) NULL,
                Reason NVARCHAR(512) NULL,
                Message NVARCHAR(1024) NULL,
                ResultJson NVARCHAR(MAX) NULL,
                Error NVARCHAR(2000) NULL,
                Attempts INT NOT NULL DEFAULT 0,
                CreatedUtc DATETIME2 NOT NULL,
                UpdatedUtc DATETIME2 NULL
            );
        ");
    }
    catch { /* Column may already exist or DB not ready */ }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("AllowManagementUI");
app.UseAuthentication();
app.UseAuthorization();

// Client-certificate validation: enforces the operator-configured trusted CA bundle on device
// endpoints when APIM is not in front (e.g. dev/direct access).
app.UseClientCertificateValidation();

// APIM gateway enforcement: device endpoints require APIM managed identity
app.UseApimGateway();

// Map API endpoints
app.MapPolicyEndpoints();
app.MapAssignmentEndpoints();
app.MapDeviceEndpoints();
app.MapMonitoringEndpoints();
app.MapCatalogEndpoints();
app.MapWebhookEndpoints();
app.MapConfigEndpoints();
app.MapCommandEndpoints();
app.MapEventGridEndpoints();

// Hub authorization is opt-in via config so the live portal feed keeps working in
// environments where the Entra delegated scope/consent isn't configured yet.
// Set Hubs:RequireAuth=true once the portal app registration has consent for the
// API's exposed scope (api://{apiClientId}/access_as_user).
var hubsRequireAuth = app.Configuration.GetValue<bool>("Hubs:RequireAuth");
var commandStatusHub = app.MapHub<CommandStatusHub>(CommandStatusHub.Path);
var policyStatusHub = app.MapHub<PolicyStatusHub>(PolicyStatusHub.Path);
if (hubsRequireAuth)
{
    commandStatusHub.RequireAuthorization();
    policyStatusHub.RequireAuthorization();
}

// Health check
app.MapGet("/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
    .WithName("HealthCheck")
    .WithTags("System");

app.Run();
