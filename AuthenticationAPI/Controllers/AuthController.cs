using Application.Interfeses;
using Application.Repository;
using Application.Services;
using Core.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using Presistence.Contracts;

namespace AuthenticationAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {

        private readonly IAuthService _authService;
        private readonly ISessionRepository _sessionRepository;

        public AuthController(IAuthService authService, ISessionRepository sessionRepository)
        {
            _authService = authService;
            _sessionRepository = sessionRepository;
        }

        [HttpGet]
        public async Task<IResult> SessionsAsync()
        {
            return Results.Json(await _sessionRepository.GetSessionsAsync());
        }

        [HttpDelete("logout")]
        public async Task<IResult> LogoutAsync([FromBody] CreateLogout Token)
        {
            Console.WriteLine(Token.AccessToken);
            Console.WriteLine(34523);
            var session = await _sessionRepository.GetSessionByAccessTokenAsync(Token.AccessToken);
            if (session != null)
            {
                (string? userId, string? sessionId) = _authService.ExtractClaimsFromToken(Token.AccessToken);
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