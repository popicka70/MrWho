namespace MrWho.Shared;

public enum AudienceMode
{
    None = 0,
    RequestedIntersection = 1,
    AllConfigured = 2,
    RequestedOrAll = 3,
    RequestedOrPrimary = 4,
    ErrorIfUnrequested = 5,
    AccessTokenOnly = 6
}
