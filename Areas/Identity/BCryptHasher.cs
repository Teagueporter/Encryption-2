using Microsoft.AspNetCore.Identity;

using BC = BCrypt.Net.BCrypt;

namespace App.Areas.Identity;
internal class BCryptHasher : IPasswordHasher<IdentityUser> {
    public string HashPassword(IdentityUser user, string password) {
        return BC.HashPassword(password, workFactor: 17);
    }
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        return BC.Verify(providedPassword, hashedPassword) 
            ? PasswordVerificationResult.Success 
            : PasswordVerificationResult.Failed;
    }

}