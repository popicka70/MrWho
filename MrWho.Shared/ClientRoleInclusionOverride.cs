namespace MrWho.Shared;

/// <summary>
/// Optional per-client override for which role sets are included in issued tokens.
/// When null, scope-based resolution is used (legacy behaviour).
/// </summary>
public enum ClientRoleInclusionOverride
{
    GlobalOnly = 0,
    ClientOnly = 1,
    GlobalAndClient = 2
}
