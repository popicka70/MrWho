using System;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MrWho.Shared.Authentication;

/// <summary>
/// Centralized helper for computing authentication scheme and cookie names
/// for Identity cookie authentication across the solution.
/// </summary>
public static class CookieSchemeNaming
{
    public const string DefaultScheme = "Identity.Application";
    public const string DefaultCookieName = ".AspNetCore.Identity.Application";

    /// <summary>
    /// Resolve the scheme and cookie names using provided identifiers and optional cookie options.
    /// Priority rules:
    /// - If <paramref name="options"/> has a Cookie.Name, that name is used for the cookie.
    /// - If <paramref name="clientName"/> is provided, names are generated per client.
    /// - Else if <paramref name="realmName"/> is provided, names are generated per realm.
    /// - Else default Identity names are used.
    /// </summary>
    /// <param name="clientName">Client name/identifier (preferred when provided).</param>
    /// <param name="realmName">Realm name (used when clientName is not provided).</param>
    /// <param name="options">Optional cookie options that may override the cookie name.</param>
    /// <returns>Tuple of (schemeName, cookieName).</returns>
    public static (string schemeName, string cookieName) ResolveNames(
        string? clientName,
        string? realmName,
        CookieAuthenticationOptions? options = null)
    {
        // Determine scheme name
        string scheme = !string.IsNullOrWhiteSpace(clientName)
            ? BuildClientScheme(clientName!)
            : !string.IsNullOrWhiteSpace(realmName)
                ? BuildRealmScheme(realmName!)
                : DefaultScheme;

        // Determine cookie name (options override if set)
        string cookie = !string.IsNullOrWhiteSpace(options?.Cookie?.Name)
            ? options!.Cookie!.Name!
            : !string.IsNullOrWhiteSpace(clientName)
                ? BuildClientCookie(clientName!)
                : !string.IsNullOrWhiteSpace(realmName)
                    ? BuildRealmCookie(realmName!)
                    : DefaultCookieName;

        return (scheme, cookie);
    }

    public static string BuildClientScheme(string clientName)
        => $"Identity.Application.{Sanitize(clientName)}";

    public static string BuildRealmScheme(string realmName)
        => $"Identity.Application.Realm.{Sanitize(realmName)}";

    public static string BuildClientCookie(string clientName)
        => $".MrWho.{Sanitize(clientName)}";

    public static string BuildRealmCookie(string realmName)
        => $".MrWho.Realm.{Sanitize(realmName)}";

    /// <summary>
    /// Normalize an identifier for inclusion in scheme/cookie names.
    /// Keeps letters, digits, '.', '_' and '-' and replaces others with '_'.
    /// </summary>
    public static string Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "Default";
        }

        ReadOnlySpan<char> src = value.AsSpan();
        Span<char> buffer = stackalloc char[src.Length];
        var i = 0;
        foreach (var ch in src)
        {
            buffer[i++] = char.IsLetterOrDigit(ch) || ch is '.' or '_' or '-' ? ch : '_';
        }
        return new string(buffer[..i]);
    }
}
