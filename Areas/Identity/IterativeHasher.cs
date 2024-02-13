using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser> {

    private const int SaltSize = 32; 
    private const int Iterations = 100000; 

    public string HashPassword(IdentityUser user, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

        using (var sha256 = SHA256.Create())
        {
            byte[] combined = Combine(salt, Encoding.UTF8.GetBytes(password));
            byte[] hash = sha256.ComputeHash(combined);

            for (int i = 1; i < Iterations; i++)
            {
                hash = sha256.ComputeHash(hash);
            }
            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
        }
    }

    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        var parts = hashedPassword.Split(':');
        if (parts.Length != 2)
        {
            return PasswordVerificationResult.Failed;
        }

        var salt = Convert.FromBase64String(parts[0]);
        var storedHash = Convert.FromBase64String(parts[1]);

        using (var sha256 = SHA256.Create())
        {
            byte[] combined = Combine(salt, Encoding.UTF8.GetBytes(providedPassword));
            byte[] hash = sha256.ComputeHash(combined);

            for (int i = 1; i < Iterations; i++)
            {
                hash = sha256.ComputeHash(hash);
            }

            return hash.SequenceEqual(storedHash) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }

    private static byte[] Combine(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, result, 0, first.Length);
        Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
        return result;
    }
}
