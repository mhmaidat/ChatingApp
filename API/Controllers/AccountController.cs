using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{



    public class AccountController: BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")] //api/account/register
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if(await UserExists(registerDto.UserName)) return BadRequest("This User Has already Exsits!");
            
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.UserName.ToLower(),
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                passwordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user),
            };
        }

        [HttpPost("login")] //api/account/login
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x => 
                x.UserName == loginDto.UserName);


            if(user == null) return Unauthorized("Invalid User Name!");
            using var hmac = new HMACSHA512(user.passwordSalt);
            var ComputedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i = 0; i < ComputedHash.Length; i++){
                if(ComputedHash[i] != user.passwordHash[i]) return Unauthorized("Invalid Password!");
            }
             return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user),
            };
        }
        private async Task<bool> UserExists(string username)
        {
                return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
        
    }
}