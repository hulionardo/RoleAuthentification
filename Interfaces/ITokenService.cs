using Microsoft.AspNetCore.Identity;

namespace RoleAuthentification.Interfaces;

public interface ITokenService
{
    public string GenerateToken(IdentityUser user, IList<string> roles);
}