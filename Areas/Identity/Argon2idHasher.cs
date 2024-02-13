using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Konscious.Security.Cryptography;
using System.Text;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by Argon2id.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class Argon2idHasher : IPasswordHasher<IdentityUser> {

    private const int SaltSize = 32; 
    private const int KeySize = 32;
    private const int DegreeOfParallelism = 8; 
    private const int Iterations = 4;    
    private const int MemorySize = 131072; 

    public string HashPassword(IdentityUser user, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

        using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password)))
        {
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DegreeOfParallelism;
            argon2.Iterations = Iterations;
            argon2.MemorySize = MemorySize;

            var key = argon2.GetBytes(KeySize);
            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(key);
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
        var storedKey = Convert.FromBase64String(parts[1]);

        using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(providedPassword)))
        {
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DegreeOfParallelism;
            argon2.Iterations = Iterations;
            argon2.MemorySize = MemorySize;

            var key = argon2.GetBytes(KeySize);
            return key.SequenceEqual(storedKey) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }

}