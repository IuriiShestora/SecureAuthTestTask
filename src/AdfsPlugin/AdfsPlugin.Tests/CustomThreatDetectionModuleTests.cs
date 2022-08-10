using AdfsPlugin.Interfaces;
using FluentAssertions;
using Microsoft.IdentityServer.Public.ThreatDetectionFramework;
using Moq;
using System;
using System.Threading.Tasks;
using Xunit;

namespace AdfsPlugin.Tests
{
    public class CustomThreatDetectionModuleTests
    {
        private readonly Mock<IExternalThreatDetectionService> _externalThreatDetectionServiceMock;
        private readonly Mock<IUserAdStatusService> _userAdStatusServiceMock;
        private readonly Mock<SecurityContext> _securityContextMock;

        public CustomThreatDetectionModuleTests()
        {
            _externalThreatDetectionServiceMock = new Mock<IExternalThreatDetectionService>();
            _userAdStatusServiceMock = new Mock<IUserAdStatusService>();

            _securityContextMock = new Mock<SecurityContext>();
            _securityContextMock.Setup(s => s.UserIdentifier).Returns("username@domain");
        }

        [Fact]
        public void Module_ShouldBlockAuthenticationImmediately_IfUserIsNotEnabledInActiveDirectory()
        {
            // Arrange
            _externalThreatDetectionServiceMock.Setup(s => s.IsAuthenticationAllowed()).Returns(() => Task.FromResult(new Random().Next(2) == 1));

            _userAdStatusServiceMock.Setup(s => s.IsEnabled(It.IsAny<string>())).Returns(false);

            var instance = new CustomThreatDetectionModule(_externalThreatDetectionServiceMock.Object, _userAdStatusServiceMock.Object, null);

            // Act
            var result = instance.EvaluatePreAuthentication(null, null, _securityContextMock.Object, null, null).Result;
            
            // Assert
            result.Should().Be(ThrottleStatus.Block);
            _userAdStatusServiceMock.Verify(s => s.IsEnabled(It.IsAny<string>()), Times.Once);
            _externalThreatDetectionServiceMock.Verify(s => s.IsAuthenticationAllowed(), Times.Never);
        }

        [Fact]
        public void Module_ShouldBlockAuthenticationImmediately_IfExternalHttpServiceReturnsFalse()
        {
            // Arrange
            _externalThreatDetectionServiceMock.Setup(s => s.IsAuthenticationAllowed()).Returns(Task.FromResult(false));

            _userAdStatusServiceMock.Setup(s => s.IsEnabled(It.IsAny<string>())).Returns(true);

            var instance = new CustomThreatDetectionModule(_externalThreatDetectionServiceMock.Object, _userAdStatusServiceMock.Object, null);

            // Act
            var result = instance.EvaluatePreAuthentication(null, null, _securityContextMock.Object, null, null).Result;

            // Assert
            result.Should().Be(ThrottleStatus.Block);
            _userAdStatusServiceMock.Verify(s => s.IsEnabled(It.IsAny<string>()), Times.Once);
            _externalThreatDetectionServiceMock.Verify(s => s.IsAuthenticationAllowed(), Times.Once);
        }

        [Fact]
        public async Task Module_ShouldAllowAuthentication_IfUserIsEnabledInActiveDirectoryAndIfExternalHttpServiceReturnsTrue()
        {
            // Arrange
            _externalThreatDetectionServiceMock.Setup(s => s.IsAuthenticationAllowed()).Returns(Task.FromResult(true));

            _userAdStatusServiceMock.Setup(s => s.IsEnabled(It.IsAny<string>())).Returns(true);

            var instance = new CustomThreatDetectionModule(_externalThreatDetectionServiceMock.Object, _userAdStatusServiceMock.Object, null);

            // Act
            var result = await instance.EvaluatePreAuthentication(null, null, _securityContextMock.Object, null, null);

            // Assert
            result.Should().Be(ThrottleStatus.Allow);
            _userAdStatusServiceMock.Verify(s => s.IsEnabled(It.IsAny<string>()), Times.Once);
            _externalThreatDetectionServiceMock.Verify(s => s.IsAuthenticationAllowed(), Times.Once);
        }
    }
}