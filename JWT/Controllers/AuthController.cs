using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class AuthController : ControllerBase
    {
        string signinKey = "OlusturulanSigningKey123456789012345678901234567890";

        [HttpGet]
        public string Get(string userName, string password)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name,userName),
                new Claim(JwtRegisteredClaimNames.Email,userName),
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signinKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                    issuer: "https://www.example.com",
                    audience: "OlusturulanTokenDegerim",
                    claims: claims,
                    expires: DateTime.Now.AddDays(15),
                    notBefore: DateTime.Now,
                    signingCredentials: credentials
                );
            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return token;
        }
        [HttpGet("ValidateToken")]
        public bool Validatetoken(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signinKey));
            try
            {
                JwtSecurityTokenHandler handler = new();
                handler.ValidateToken(token, new TokenValidationParameters()
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = securityKey,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                    ValidateIssuer = false

                }, out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken;
                var claims = jwtToken.Claims.ToList();
                return true;
            }
            catch (Exception)
            {

                return false;
            }
        }
    }
}
