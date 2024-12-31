using Login;
using Login.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Numerics;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly LoginDbContext _context;
    private readonly byte[] Key;
    private readonly byte[] IV;

    public UserController(LoginDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
        Key = GenerateKey(_configuration["SecretKey"]);
        IV = new byte[16]; // Initialize IV as needed
    }

    //public async Task<User> GetUserById(int userId)
    //{
    //    var user = await _context.Users.FindAsync(userId);
    //    return user;
    //}

    [HttpPost("CreateUser")]
    public async Task<IActionResult> CreateUser([FromBody] UserRequest userRequest)
    {
        byte[] encryptedPassword = EncryptPassword(userRequest.Password);

        var user = new User
        {
            UserName = userRequest.UserName,
            Password = encryptedPassword
        };
        _context.Users.Add(user);
        _context.SaveChangesAsync();
        return Ok(new { message = "User created successfully" });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserRequest userRequest)
    {

        // Find the user by username
        var user = await _context.Users.FirstOrDefaultAsync(u => u.UserName == userRequest.UserName);

        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }
        string decryptedPassword = DecryptPassword(user.Password);

        // Compare the provided password (byte[]) with the stored password (byte[])
        if (userRequest.Password != decryptedPassword)
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }

        return Ok(new { message = "Login successful" });
    }


    private byte[] EncryptPassword(string password)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;
            aes.Padding = PaddingMode.PKCS7; // Ensure padding is set
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(password);
                    }
                }
                return ms.ToArray();
            }
        }
    }

    private string DecryptPassword(byte[] encryptedPassword)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;
            aes.Padding = PaddingMode.PKCS7; // Ensure padding is set
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream(encryptedPassword))
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }

    private byte[] GenerateKey(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

}
