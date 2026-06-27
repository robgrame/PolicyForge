using System.Text.Json;
using PolicyForge.Contracts.Configuration;

namespace PolicyForge.Api.Providers;

/// <summary>
/// Base for providers whose authored payload is applied natively by a dedicated client handler
/// (i.e. not compiled down to another provider). Compilation is a single pass-through instruction.
/// </summary>
public abstract class PassthroughProviderBase<TPayload> : IConfigurationProvider
{
    public abstract ProviderType Type { get; }

    /// <summary>Validate the deserialized payload, returning any error messages.</summary>
    protected abstract IReadOnlyList<string> ValidatePayload(TPayload payload);

    /// <summary>Resolve the instruction action (defaults to Set).</summary>
    protected virtual string ResolveAction(TPayload payload) => "Set";

    public ProviderValidationResult Validate(string payloadJson)
    {
        TPayload payload;
        try
        {
            payload = JsonSerializer.Deserialize<TPayload>(payloadJson, ConfigurationJson.Options)
                      ?? throw new JsonException("payload is null");
        }
        catch (JsonException ex)
        {
            return ProviderValidationResult.Fail($"Invalid {Type} payload: {ex.Message}");
        }

        var errors = ValidatePayload(payload);
        return errors.Count == 0 ? ProviderValidationResult.Ok : ProviderValidationResult.Fail(errors.ToArray());
    }

    public IReadOnlyList<ResolvedInstruction> Compile(ConfigurationItem item)
    {
        var payload = item.DeserializePayload<TPayload>();
        return new[]
        {
            new ResolvedInstruction
            {
                Provider = Type,
                Action = ResolveAction(payload),
                Data = ProviderJson.ToElement(payload),
                SourceItemId = item.Id,
                Name = item.Name,
            }
        };
    }

    protected static string SetOrRemove(EnsureState ensure) => ensure == EnsureState.Absent ? "Remove" : "Set";
}
