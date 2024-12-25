using Microsoft.AspNetCore.Mvc;
using TestApiJWT.Models;
using TestApiJWT.Services;

namespace TestApiJWT.Controllers
{
    [Route("api/[controller]")] // Define the route for this controller
    [ApiController] // Specify that this is an API controller
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        // Constructor to initialize the AuthService
        // المُنشئ لتهيئة خدمة المصادقة
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // Endpoint to register a new user
        // نقطة نهاية لتسجيل مستخدم جديد
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            // Validate the request body
            // التحقق من صحة البيانات المرسلة
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Call the AuthService to handle the registration logic
            // استدعاء خدمة المصادقة لتنفيذ منطق التسجيل
            var result = await _authService.RegisterAsync(model);

            // Return an error message if authentication fails
            // إرجاع رسالة خطأ إذا فشلت عملية المصادقة
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(result);
        }

        // Endpoint to authenticate a user and generate a token
        // نقطة نهاية لمصادقة المستخدم وإنشاء رمز JWT
        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            // Validate the request body
            // التحقق من صحة البيانات المرسلة
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Call the AuthService to handle token generation
            // استدعاء خدمة المصادقة لإنشاء الرمز
            var result = await _authService.GetTokenAsync(model);

            // Return an error message if authentication fails
            // إرجاع رسالة خطأ إذا فشلت عملية المصادقة
            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(result);
        }

        // Endpoint to add a role to an existing user
        // نقطة نهاية لإضافة دور إلى مستخدم موجود
        [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            // Validate the request body
            // التحقق من صحة البيانات المرسلة
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Call the AuthService to handle role assignment
            // استدعاء خدمة المصادقة لتعيين الدور
            var result = await _authService.AddRoleAsync(model);

            // Return an error message if the operation fails
            // إرجاع رسالة خطأ إذا فشلت العملية
            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            // Return the successful result
            // إرجاع النتيجة الناجحة
            return Ok(model);
        }
    }
}
