using Application.Repository;
using Application.Services;
using Core.Models;
using Microsoft.AspNetCore.Mvc;
using Presistence.Contracts;

namespace AuthenticationAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {

        private readonly AuthService _authService;
        private readonly SessionRepository _sessionRepository;

        public AuthController(AuthService authService, SessionRepository sessionRepository)
        {
            _authService = authService;
            _sessionRepository = sessionRepository;
        }

        [HttpDelete("logout")]
        public async Task<IResult> LogoutAsync([FromBody] string AccessToken)
        {
            var session = await _sessionRepository.GetSessionByAccessTokenAsync(AccessToken);
            if (session != null)
            {
                (string? userId, string? sessionId) = _authService.ExtractClaimsFromToken(AccessToken);
                Guid.TryParse(sessionId, out var newSessionId);
                var tokens = await _sessionRepository.RemoveSessionAsync(newSessionId);
                if (tokens != null)
                    return Results.Json(tokens);
            }
            return Results.BadRequest();
        }

        [HttpPost("login")]
        public async Task<IResult> LoginAsync([FromBody] CreateUser user)
        {
            if (user == null || string.IsNullOrWhiteSpace(user.login) || string.IsNullOrWhiteSpace(user.password))
                return Results.BadRequest();

            JwtTokenModel? tokens = await _authService.AuthenticationUserAsync(user.login, user.password);

            if (tokens != null)
                return Results.Json(tokens);

            return Results.Unauthorized();
        }

        [HttpPut("refreshToken")]
        public async Task<IResult> RefreshAsync([FromBody] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return Results.BadRequest();

            var tokens = await _authService.RefreshTokensAsync(refreshToken);
            if (tokens == null)
            {
                return Results.Unauthorized();
            }
            return Results.Json(tokens);
        }
    }
}