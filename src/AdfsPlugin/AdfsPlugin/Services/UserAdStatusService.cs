using AdfsPlugin.Interfaces;
using System.DirectoryServices.AccountManagement;

namespace AdfsPlugin.Services
{
    /// <summary>
    /// Service to lookup Active Directory to find a user by UserName.
    /// </summary>
    internal class UserAdStatusService : IUserAdStatusService
    {
        /// <summary>
        /// Validates a User Status in Active Directory by UserName.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns>True if User is Enabled, False otherwise, null if User is not found in Active Directory.</returns>
        public bool? IsEnabled(string userName)
        {
            using (var ctx = new PrincipalContext(ContextType.Domain))
            {
                var user = UserPrincipal.FindByIdentity(ctx, userName);
                return user?.Enabled;
            }
        }
    }
}
