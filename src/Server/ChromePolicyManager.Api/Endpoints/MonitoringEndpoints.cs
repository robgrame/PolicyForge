using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class MonitoringEndpoints
{
    public static void MapMonitoringEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/monitoring").WithTags("Monitoring");

        group.MapGet("/dashboard", async (DeviceReportingService service) =>
        {
            var dashboard = await service.GetDashboardAsync();
            // Map to client DTO format
            return Results.Ok(new
            {
                dashboard.TotalDevices,
                dashboard.CompliantDevices,
                dashboard.NonCompliantDevices,
                dashboard.ErrorDevices,
                dashboard.OfflineDevices,
                RecentReports = dashboard.RecentReports.Select(d => new
                {
                    d.DeviceId,
                    d.DeviceName,
                    Status = d.LastStatus.ToString(),
                    AppliedPolicyHash = d.LastAppliedPolicyHash,
                    Errors = d.LastError,
                    d.ChromeVersion,
                    d.OsVersion,
                    d.OsBuild,
                    d.Manufacturer,
                    d.Model,
                    d.ScriptVersion,
                    LastContact = d.LastCheckIn ?? DateTime.MinValue,
                    PolicyKeysWritten = 0,
                    PolicyKeysRemoved = 0
                })
            });
        }).WithName("GetDashboard");

        group.MapGet("/offline-devices", async (DeviceReportingService service, int? hoursThreshold) =>
        {
            var devices = await service.GetOfflineDevicesAsync(hoursThreshold ?? 24);
            return Results.Ok(devices.Select(d => new
            {
                d.DeviceId,
                d.DeviceName,
                Status = d.LastStatus.ToString(),
                AppliedPolicyHash = d.LastAppliedPolicyHash,
                Errors = d.LastError,
                d.ChromeVersion,
                d.OsVersion,
                d.OsBuild,
                d.Manufacturer,
                d.Model,
                d.ScriptVersion,
                LastContact = d.LastCheckIn ?? DateTime.MinValue,
                PolicyKeysWritten = 0,
                PolicyKeysRemoved = 0
            }));
        }).WithName("GetOfflineDevices");

        group.MapGet("/error-devices", async (DeviceReportingService service) =>
        {
            var devices = await service.GetDevicesWithErrorsAsync();
            return Results.Ok(devices.Select(d => new
            {
                d.DeviceId,
                d.DeviceName,
                Status = d.LastStatus.ToString(),
                AppliedPolicyHash = d.LastAppliedPolicyHash,
                Errors = d.LastError,
                d.ChromeVersion,
                d.OsVersion,
                d.OsBuild,
                d.Manufacturer,
                d.Model,
                d.ScriptVersion,
                LastContact = d.LastCheckIn ?? DateTime.MinValue,
                PolicyKeysWritten = 0,
                PolicyKeysRemoved = 0
            }));
        }).WithName("GetErrorDevices");

        // Trigger on-demand proactive remediation for a single device
        group.MapPost("/devices/{deviceId}/trigger-remediation", async (string deviceId, PushRemediationService pushService) =>
        {
            var result = await pushService.DispatchToDeviceAsync(deviceId, "Manual trigger from admin UI", "Admin");
            return result.Skipped
                ? Results.BadRequest(new { result.Message })
                : Results.Ok(new { result.Message, result.CommandsSent, result.CommandsFailed });
        }).WithName("TriggerDeviceRemediation");
    }
}
