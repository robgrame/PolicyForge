using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<PolicySet> PolicySets => Set<PolicySet>();
    public DbSet<PolicySetVersion> PolicySetVersions => Set<PolicySetVersion>();
    public DbSet<PolicyAssignment> PolicyAssignments => Set<PolicyAssignment>();
    public DbSet<DeviceReport> DeviceReports => Set<DeviceReport>();
    public DbSet<DeviceState> DeviceStates => Set<DeviceState>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<PolicyCatalogEntry> PolicyCatalog => Set<PolicyCatalogEntry>();
    public DbSet<DeviceLog> DeviceLogs => Set<DeviceLog>();
    public DbSet<PrivilegedCommand> PrivilegedCommands => Set<PrivilegedCommand>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<PolicySet>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Name).IsUnique();
            e.HasMany(x => x.Versions).WithOne(x => x.PolicySet).HasForeignKey(x => x.PolicySetId);
        });

        modelBuilder.Entity<PolicySetVersion>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.PolicySetId, x.Version }).IsUnique();
            e.HasMany(x => x.Assignments).WithOne(x => x.PolicySetVersion).HasForeignKey(x => x.PolicySetVersionId);
        });

        modelBuilder.Entity<PolicyAssignment>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.PolicySetVersionId, x.EntraGroupId }).IsUnique();
        });

        modelBuilder.Entity<DeviceReport>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.DeviceId);
            e.HasIndex(x => x.ReportedAt);
        });

        modelBuilder.Entity<DeviceState>(e =>
        {
            e.HasKey(x => x.DeviceId);
            e.HasIndex(x => x.LastCheckIn);
        });

        modelBuilder.Entity<AuditLog>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Timestamp);
            e.HasIndex(x => new { x.EntityType, x.EntityId });
        });

        modelBuilder.Entity<PolicyCatalogEntry>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.Name, x.IsRecommended }).IsUnique();
            e.HasIndex(x => x.Category);
            e.HasIndex(x => x.DataType);
        });

        modelBuilder.Entity<DeviceLog>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.DeviceId);
            e.HasIndex(x => x.ReceivedAt);
            e.HasIndex(x => new { x.DeviceId, x.ClientTimestamp });
        });

        modelBuilder.Entity<PrivilegedCommand>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.CreatedUtc);
        });
    }
}
