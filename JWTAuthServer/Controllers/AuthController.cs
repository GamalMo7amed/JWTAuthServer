using JWTAuthServer.Data;
using JWTAuthServer.DTOs;
using JWTAuthServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

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
            var refreshToken = GenerateRefreshToken();
            var hashedRefreshToken = HashToken(refreshToken);
            var refreshTokenEntity = new RefreshToken
            {
                Token = hashedRefreshToken,
                UserId = user.Id,
                ClientId = client.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            
            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();
            return Ok(new RefreshTokenResponseDTO
            {
                Token = token,
                RefreshToken = refreshToken
            });
        }
        [Authorize]
        [HttpPost("Logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequestDTO requestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return Unauthorized("Invalid access token.");
            }
            
            if (!int.TryParse(userIdClaim.Value, out int userId))
            {
                return Unauthorized("Invalid user ID in access token.");
            }
            var hashedToken = HashToken(requestDto.RefreshToken);
            var storedRefreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .Include(rt => rt.Client)
                .FirstOrDefaultAsync(rt => rt.Token == hashedToken && rt.Client.ClientId == requestDto.ClientId && rt.UserId == userId);
            if (storedRefreshToken == null)
            {
                return Unauthorized("Invalid refresh token.");
            }
            if (storedRefreshToken.IsRevoked)
            {
                return BadRequest("Refresh token is already revoked.");
            }
            storedRefreshToken.IsRevoked = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;
            if (requestDto.IsLogoutFromAllDevices)
            {
                var userRefreshTokens = await _context.RefreshTokens
                    .Where(rt => rt.UserId == storedRefreshToken.UserId && !rt.IsRevoked)
                    .ToListAsync();
                foreach (var token in userRefreshTokens)
                {
                    token.IsRevoked = true;
                    token.RevokedAt = DateTime.UtcNow;
                }
            }
            await _context.SaveChangesAsync();
            return Ok(new
            {
                Message = "Logout successful. Refresh token has been revoked."
            });
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
        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDTO requestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var hashedToken = HashToken(requestDto.RefreshToken);
            var storedRefreshToken = await _context.RefreshTokens.Include(rt => rt.User).ThenInclude(rt => rt.UserRoles).ThenInclude(rt => rt.Role)
                .Include(rt => rt.Client).FirstOrDefaultAsync(rt => rt.Token == hashedToken && rt.Client.ClientId == requestDto.ClientId);
            if (storedRefreshToken == null)
            {
                return Unauthorized("Invalid refresh token.");
            }
            if (storedRefreshToken.IsRevoked)
            {
                return Unauthorized("Refresh token has been revoked.");
            }
            if (storedRefreshToken.ExpiresAt < DateTime.UtcNow)
            {
                return Unauthorized("Refresh token has expired.");
            }
            var user = storedRefreshToken.User;
            var client = storedRefreshToken.Client;
            storedRefreshToken.IsRevoked = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;
            var newRefreshToken = GenerateRefreshToken();
            var hashedNewRefreshToken = HashToken(newRefreshToken);
            var newRefreshTokenEntity = new RefreshToken
            {
                Token = hashedNewRefreshToken,
                UserId = user.Id,
                ClientId = client.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7), // Adjust as needed
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            _context.RefreshTokens.Add(newRefreshTokenEntity);
            // Generate new JWT access token
            var newJwtToken = GenerateJwtToken(user, client);
            // Save changes to the database
            await _context.SaveChangesAsync();
            return Ok(new RefreshTokenResponseDTO
            {
                Token = newJwtToken,
                RefreshToken = newRefreshToken
            });
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
