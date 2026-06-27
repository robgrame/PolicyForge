using System.ComponentModel.DataAnnotations;
using ChromePolicyManager.Contracts;

namespace ChromePolicyManager.Api.Models;

/// <summary>
/// Persistent record of a privileged command enqueued for the Worker.
/// Tracks lifecycle status updated by the API status relay (fed by the Worker over the
/// cpm-command-status queue) and surfaced to the portal via SignalR.
/// </summary>
public class PrivilegedCommand
{
    [Key]
    public Guid Id { get; set; }

    public PrivilegedCommandType Type { get; set; }

    public CommandStatus Status { get; set; } = CommandStatus.Pending;

    [MaxLength(2000)]
    public string? PayloadJson { get; set; }

    [MaxLength(256)]
    public string? Actor { get; set; }

    [MaxLength(512)]
    public string? Reason { get; set; }

    [MaxLength(1024)]
    public string? Message { get; set; }

    public string? ResultJson { get; set; }

    [MaxLength(2000)]
    public string? Error { get; set; }

    public int Attempts { get; set; }

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedUtc { get; set; }
}
