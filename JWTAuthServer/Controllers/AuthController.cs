using JWTAuthServer.Data;
using JWTAuthServer.DTOs;
using JWTAuthServer.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTAuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;

        public AuthController(IConfiguration configuration, ApplicationDbContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var client = _context.Clients.FirstOrDefault(c => c.ClientId == loginDto.ClientId);
            if (client == null)
            {
                return Unauthorized("Invalid client credentials.");
            }
            var user = await _context.Users.Include(u => u.UserRoles).ThenInclude(u => u.Role)
                .FirstOrDefaultAsync(u => u.Email.ToLower() == loginDto.Email.ToLower());
            if(user == null)
            {
                return Unauthorized("Invalid credentials.");
            }
            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(loginDto.Password,user.Password);
            if (!isPasswordValid)
            {
                return Unauthorized("Invalid credentials.");
            }
            var token = GenerateJwtToken(user, client);
            return Ok(new { Token = token });
        }
        // Private method responsible for generating a JWT token for an authenticated user
        private string GenerateJwtToken(User user, Client client)
        {
            var signingKey = _context.SigningKeys.FirstOrDefault(K => K.IsActive);
            if (signingKey == null)
            {
                throw new Exception("No active signing key available.");
            }
            var privateKeyBytes = Convert.FromBase64String(signingKey.PrivateKey);
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
            var rsaSecurityKey = new RsaSecurityKey(rsa)
            {
                KeyId = signingKey.KeyId
            };
            var creds = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name,user.FirstName),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.NameIdentifier,user.Email)
            };
            foreach (var userRole in user.UserRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name));
            }
            var tokenDescriptor = new JwtSecurityToken
                (
                issuer: _configuration["Jwt:Issuer"],
                audience:client.ClientURL,
                claims:claims,
                expires:DateTime.UtcNow.AddHours(1),
                signingCredentials:creds
                );
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.WriteToken(tokenDescriptor);
            return token;   
        }
    }
}
