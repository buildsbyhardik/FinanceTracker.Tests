using FinanceTracker.API.Application.DTOs;
using FinanceTracker.API.Controllers;
using FinanceTracker.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace FinanceTracker.Tests.Controllers
{
    public class AuthControllerTests
    {
        private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
        private readonly Mock<SignInManager<ApplicationUser>> _signInManagerMock;
        private readonly Mock<IConfiguration> _configurationMock;
        private readonly AuthController _controller;

        public AuthControllerTests()
        {
            var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
            var optionsMock = new Mock<Microsoft.Extensions.Options.IOptions<IdentityOptions>>();
            var passwordHasherMock = new Mock<IPasswordHasher<ApplicationUser>>();
            var userValidators = new List<IUserValidator<ApplicationUser>>();
            var passwordValidators = new List<IPasswordValidator<ApplicationUser>>();
            var keyNormalizerMock = new Mock<ILookupNormalizer>();
            var errorsMock = new Mock<IdentityErrorDescriber>();
            var servicesMock = new Mock<IServiceProvider>();
            var loggerMock = new Mock<Microsoft.Extensions.Logging.ILogger<UserManager<ApplicationUser>>>();

            _userManagerMock = new Mock<UserManager<ApplicationUser>>(
                userStoreMock.Object,
                optionsMock.Object,
                passwordHasherMock.Object,
                userValidators,
                passwordValidators,
                keyNormalizerMock.Object,
                errorsMock.Object,
                servicesMock.Object,
                loggerMock.Object);

            var contextAccessorMock = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            var userClaimsPrincipalFactoryMock = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
            var signInLoggerMock = new Mock<Microsoft.Extensions.Logging.ILogger<SignInManager<ApplicationUser>>>();

            _signInManagerMock = new Mock<SignInManager<ApplicationUser>>(
                _userManagerMock.Object,
                contextAccessorMock.Object,
                userClaimsPrincipalFactoryMock.Object,
                optionsMock.Object,
                signInLoggerMock.Object,
                null,
                null);

            _configurationMock = new Mock<IConfiguration>();
            _configurationMock.Setup(c => c["Jwt:Key"]).Returns("sK9n3X$ZpLmY8!wR2@a#C^bT%fJ1Vu7NdKq0Hg6MxzEtPiLd");
            _configurationMock.Setup(c => c["Jwt:Issuer"]).Returns("https://localhost:7273");
            _configurationMock.Setup(c => c["Jwt:Audience"]).Returns("FinanceTracker.Client");

            _controller = new AuthController(
                _userManagerMock.Object,
                _signInManagerMock.Object,
                _configurationMock.Object
            );

            _userManagerMock.Setup(x => x.SupportsUserEmail).Returns(true);
        }
        [Fact]
        public async Task Login_ReturnsOk_WhenCredentialsAreValid()
        {
            // Arrange
            var loginDto = new LoginDto { Email = "user@example.com", Password = "Mys@l#12345678" };
            var user = new ApplicationUser { Id = "5d99ab63-bfc5-4bd5-b64c-d7b05c5ebd81", UserName = "user@example.com", Email = loginDto.Email };
            _userManagerMock.Setup(x => x.FindByEmailAsync(loginDto.Email))
                .ReturnsAsync(user);
            _userManagerMock.Setup(x => x.CheckPasswordAsync(user, loginDto.Password))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.Login(loginDto);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var value = okResult.Value;
            Assert.NotNull(value);

            // Access properties using reflection:
            var token = value.GetType().GetProperty("token")?.GetValue(value, null);
            var expiration = value.GetType().GetProperty("expiration")?.GetValue(value, null);

            Assert.NotNull(token);
            Assert.NotNull(expiration);
        }

        [Fact]
        public async Task Login_ReturnsUnauthorized_WhenUserNotFound()
        {
            // Arrange
            var loginDto = new LoginDto { Email = "notfound@example.com", Password = "Password123!" };
            _userManagerMock.Setup(x => x.FindByEmailAsync(loginDto.Email))
                .ReturnsAsync((ApplicationUser)null);

            // Act
            var result = await _controller.Login(loginDto);

            // Assert
            Assert.IsType<UnauthorizedResult>(result);
        }

        [Fact]
        public async Task Login_ReturnsUnauthorized_WhenPasswordIsInvalid()
        {
            // Arrange
            var loginDto = new LoginDto { Email = "test@example.com", Password = "WrongPassword!" };
            var user = new ApplicationUser { Id = "user-id", UserName = "testuser", Email = loginDto.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(loginDto.Email))
                .ReturnsAsync(user);
            _userManagerMock.Setup(x => x.CheckPasswordAsync(user, loginDto.Password))
                .ReturnsAsync(false);

            // Act
            var result = await _controller.Login(loginDto);

            // Assert
            Assert.IsType<UnauthorizedResult>(result);
        }

        [Fact]
        public async Task Register_ReturnsOk_WhenUserIsCreated()
        {
            // Arrange
            var registerDto = new RegisterDto { Email = "newuser@example.com", Password = "Password123!" };
            _userManagerMock.Setup(x => x.FindByEmailAsync(registerDto.Email))
                .ReturnsAsync((ApplicationUser)null);

            var identityResult = IdentityResult.Success;
            _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerDto.Password))
                .ReturnsAsync(identityResult);

            // Act
            var result = await _controller.Register(registerDto);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);

            var value = okResult.Value;
            var status = value.GetType().GetProperty("Status")?.GetValue(value, null);
            Assert.Equal("Success", status);
        }

        [Fact]
        public async Task Register_ReturnsBadRequest_WhenPayloadIsInvalid()
        {
            // Arrange
            RegisterDto registerDto = null;

            // Act
            var result = await _controller.Register(registerDto);

            // Assert
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal("Invalid payload", badRequest.Value);
        }

        [Fact]
        public async Task Register_ReturnsError_WhenUserAlreadyExists()
        {
            // Arrange
            var registerDto = new RegisterDto { Email = "user@example.com", Password = "Mys@l#12345678" };
            var existingUser = new ApplicationUser { Email = registerDto.Email };
            _userManagerMock.Setup(x => x.FindByEmailAsync(registerDto.Email))
                .ReturnsAsync(existingUser);

            // Act
            var result = await _controller.Register(registerDto);

            // Assert
            var statusResult = Assert.IsType<ObjectResult>(result);
            Assert.Equal(400, statusResult.StatusCode);

            var value = statusResult.Value;
            var status = value.GetType().GetProperty("Status")?.GetValue(value, null);
            var message = value.GetType().GetProperty("Message")?.GetValue(value, null);

            Assert.Equal("Error", status);
            Assert.Equal("User already exists!", message);
        }

        [Fact]
        public async Task Register_ReturnsError_WhenUserCreationFails()
        {
            // Arrange
            var registerDto = new RegisterDto { Email = "failuser@example.com", Password = "12" };
            _userManagerMock.Setup(x => x.FindByEmailAsync(registerDto.Email))  
                .ReturnsAsync((ApplicationUser)null);

            var identityResult = IdentityResult.Failed(new IdentityError { Description = "Password too weak" });
            _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registerDto.Password))
                .ReturnsAsync(identityResult);

            // Act
            var result = await _controller.Register(registerDto);

            // Assert
            var statusResult = Assert.IsType<ObjectResult>(result);
            var value = statusResult.Value;
     
            Assert.Equal(500, statusResult.StatusCode);
            var status = value.GetType().GetProperty("Status")?.GetValue(value, null);
            var message = value.GetType().GetProperty("Message")?.GetValue(value, null);
            var errors = value.GetType().GetProperty("Errors")?.GetValue(value, null);

            Assert.Equal("Error", status);
            Assert.Equal("User creation failed!", message);
            Assert.Contains("Password too weak", errors as IEnumerable<string>);
        }
    }
}