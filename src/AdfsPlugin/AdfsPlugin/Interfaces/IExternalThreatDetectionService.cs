using AdfsPlugin.Models;
using System.Threading.Tasks;

namespace AdfsPlugin.Interfaces
{
    public interface IExternalThreatDetectionService
    {
        Task<bool> IsAuthenticationAllowed();
        void UpdateConfiguration(HttpClientConfig config);
    }
}
