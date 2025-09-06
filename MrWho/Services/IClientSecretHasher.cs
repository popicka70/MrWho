namespace MrWho.Services;

public interface IClientSecretHasher
{
    string HashSecret(string secret);
    bool Verify(string secret, string storedHash);
}
