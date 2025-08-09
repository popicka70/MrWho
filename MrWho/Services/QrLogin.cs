using System.Collections.Concurrent;

namespace MrWho.Services;

public sealed class QrLoginTicket
{
    public required string Token { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public string? ReturnUrl { get; init; }
    public string? ClientId { get; init; }
    public string? ApprovedUserId { get; set; }
    public bool Completed { get; set; }
}

public interface IQrLoginStore
{
    QrLoginTicket Create(string? returnUrl, string? clientId, TimeSpan? ttl = null);
    QrLoginTicket? Get(string token);
    bool Approve(string token, string userId);
    bool Complete(string token);
}

public sealed class InMemoryQrLoginStore : IQrLoginStore
{
    private readonly ConcurrentDictionary<string, QrLoginTicket> _tickets = new();
    private static string NewToken() => Convert.ToBase64String(Guid.NewGuid().ToByteArray())
        .Replace("+", "-").Replace("/", "_").TrimEnd('=');

    public QrLoginTicket Create(string? returnUrl, string? clientId, TimeSpan? ttl = null)
    {
        var token = NewToken();
        var ticket = new QrLoginTicket
        {
            Token = token,
            ExpiresAt = DateTimeOffset.UtcNow.Add(ttl ?? TimeSpan.FromMinutes(3)),
            ReturnUrl = returnUrl,
            ClientId = clientId
        };
        _tickets[token] = ticket;
        return ticket;
    }

    public QrLoginTicket? Get(string token)
    {
        if (_tickets.TryGetValue(token, out var t))
        {
            if (t.ExpiresAt <= DateTimeOffset.UtcNow || t.Completed)
            {
                _tickets.TryRemove(token, out _);
                return null;
            }
            return t;
        }
        return null;
    }

    public bool Approve(string token, string userId)
    {
        var t = Get(token);
        if (t is null) return false;
        t.ApprovedUserId = userId;
        return true;
    }

    public bool Complete(string token)
    {
        if (_tickets.TryGetValue(token, out var t))
        {
            t.Completed = true;
            _tickets.TryRemove(token, out _);
            return true;
        }
        return false;
    }
}
