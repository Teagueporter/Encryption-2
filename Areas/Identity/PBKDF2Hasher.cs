using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;
internal class PBKDF2Hasher : IPasswordHasher<IdentityUser> {

     private const int SaltSize = 32; 
    private const int KeySize = 32; 
    private const int Iterations = 100000; 
    public string HashPassword(IdentityUser user, string password) {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256)) {
            var key = pbkdf2.GetBytes(KeySize);
            return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(key);
        }
    }
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        var parts = hashedPassword.Split(':');
        if (parts.Length != 2) {
            return PasswordVerificationResult.Failed;
        }

        var salt = Convert.FromBase64String(parts[0]);
        var storedKey = Convert.FromBase64String(parts[1]);

        using (var pbkdf2 = new Rfc2898DeriveBytes(providedPassword, salt, Iterations, HashAlgorithmName.SHA256)) {
            var key = pbkdf2.GetBytes(KeySize);
            return key.SequenceEqual(storedKey) ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }

}