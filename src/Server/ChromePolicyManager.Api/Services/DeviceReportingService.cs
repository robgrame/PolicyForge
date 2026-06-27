using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

public class DeviceReportingService
{
    private readonly AppDbContext _db;

    public DeviceReportingService(AppDbContext db)
    {
        _db = db;
    }

    public async Task<DeviceReport> SubmitReportAsync(DeviceReportRequest request)
    {
        var report = new DeviceReport
        {
            DeviceId = request.DeviceId,
            DeviceName = request.DeviceName,
            UserPrincipalName = request.UserPrincipalName,
            AppliedPolicyHash = request.AppliedPolicyHash,
            AppliedVersion = request.AppliedVersion,
            Status = request.Status,
            Errors = request.Errors,
            ChromeVersion = request.ChromeVersion,
            OsVersion = request.OsVersion,
            OsBuild = request.OsBuild,
            Manufacturer = request.Manufacturer,
            Model = request.Model,
            ScriptVersion = request.ScriptVersion,
            PolicyKeysWritten = request.PolicyKeysWritten,
            PolicyKeysRemoved = request.PolicyKeysRemoved,
            ReportedAt = DateTime.UtcNow
        };

        _db.DeviceReports.Add(report);

        // Upsert device state
        var deviceState = await _db.DeviceStates.FindAsync(request.DeviceId);
        if (deviceState == null)
        {
            deviceState = new DeviceState { DeviceId = request.DeviceId };
            _db.DeviceStates.Add(deviceState);
        }

        deviceState.DeviceName = request.DeviceName;
        deviceState.UserPrincipalName = request.UserPrincipalName;
        deviceState.LastAppliedPolicyHash = request.AppliedPolicyHash;
        deviceState.LastAppliedVersion = request.AppliedVersion;
        deviceState.LastStatus = request.Status;
        deviceState.LastCheckIn = DateTime.UtcNow;
        deviceState.LastError = request.Status == DeviceComplianceStatus.Error ? request.Errors : null;
        deviceState.ChromeVersion = request.ChromeVersion;
        deviceState.OsVersion = request.OsVersion;
        deviceState.OsBuild = request.OsBuild;
        deviceState.Manufacturer = request.Manufacturer;
        deviceState.Model = request.Model;
        if (!string.IsNullOrEmpty(request.ScriptVersion))
            deviceState.ScriptVersion = request.ScriptVersion;

        await _db.SaveChangesAsync();
        return report;
    }

    public async Task<MonitoringDashboard> GetDashboardAsync()
    {
        var totalDevices = await _db.DeviceStates.CountAsync();
        var compliantDevices = await _db.DeviceStates.CountAsync(d => d.LastStatus == DeviceComplianceStatus.Compliant);
        var errorDevices = await _db.DeviceStates.CountAsync(d => d.LastStatus == DeviceComplianceStatus.Error);
        var offlineThreshold = DateTime.UtcNow.AddHours(-24);
        var offlineDevices = await _db.DeviceStates.CountAsync(d => d.LastCheckIn < offlineThreshold);
        var neverCheckedIn = await _db.DeviceStates.CountAsync(d => d.LastCheckIn == null);

        var recentReports = await _db.DeviceStates
            .OrderByDescending(d => d.LastCheckIn)
            .Take(100)
            .ToListAsync();

        return new MonitoringDashboard
        {
            TotalDevices = totalDevices,
            CompliantDevices = compliantDevices,
            NonCompliantDevices = totalDevices - compliantDevices - errorDevices,
            ErrorDevices = errorDevices,
            OfflineDevices = offlineDevices,
            NeverCheckedIn = neverCheckedIn,
            RecentReports = recentReports,
            LastUpdated = DateTime.UtcNow
        };
    }

    public async Task<List<DeviceState>> GetOfflineDevicesAsync(int hoursThreshold = 24)
    {
        var threshold = DateTime.UtcNow.AddHours(-hoursThreshold);
        return await _db.DeviceStates
            .Where(d => d.LastCheckIn < threshold || d.LastCheckIn == null)
            .OrderBy(d => d.LastCheckIn)
            .ToListAsync();
    }

    public async Task<List<DeviceState>> GetDevicesWithErrorsAsync()
    {
        return await _db.DeviceStates
            .Where(d => d.LastStatus == DeviceComplianceStatus.Error)
            .OrderByDescending(d => d.LastCheckIn)
            .ToListAsync();
    }

    public async Task<List<DeviceReport>> GetDeviceHistoryAsync(string deviceId, int count = 20)
    {
        return await _db.DeviceReports
            .Where(r => r.DeviceId == deviceId)
            .OrderByDescending(r => r.ReportedAt)
            .Take(count)
            .ToListAsync();
    }
}

public class DeviceReportRequest
{
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string? UserPrincipalName { get; set; }
    public string AppliedPolicyHash { get; set; } = string.Empty;
    public string? AppliedVersion { get; set; }
    public DeviceComplianceStatus Status { get; set; }
    public string? Errors { get; set; }
    public string? ChromeVersion { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? ScriptVersion { get; set; }
    public int? PolicyKeysWritten { get; set; }
    public int? PolicyKeysRemoved { get; set; }
}

public class MonitoringDashboard
{
    public int TotalDevices { get; set; }
    public int CompliantDevices { get; set; }
    public int NonCompliantDevices { get; set; }
    public int ErrorDevices { get; set; }
    public int OfflineDevices { get; set; }
    public int NeverCheckedIn { get; set; }
    public List<DeviceState> RecentReports { get; set; } = [];
    public DateTime LastUpdated { get; set; }
}
