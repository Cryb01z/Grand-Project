using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace ASM_Backend.Utilities;

public static class PasswordHelper
{
    public static string HashPassword(string password)
    {
        // Generate a 128-bit salt using a sequence of
        // cryptographically strong random bytes.
        byte[] salt = RandomNumberGenerator.GetBytes(128 / 8); // divide by 8 to convert bits to bytes
        string saltString = Convert.ToBase64String(salt);
        
        // derive a 256-bit subkey (use HMACSHA256 with 1000 iterations)
        string hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 1000,
            numBytesRequested: 256 / 8));
        
        return $"{hashedPassword}.{saltString}";
    }
    
    public static bool VerifyPassword(string password, string hashedPassword)
    {
        string[] passwordParts = hashedPassword.Split('.');

        byte[] salt = Convert.FromBase64String(passwordParts[1]);
        string hashedPasswordToCheck = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 1000,
            numBytesRequested: 256 / 8));

        return hashedPasswordToCheck == passwordParts[0];
    }
}