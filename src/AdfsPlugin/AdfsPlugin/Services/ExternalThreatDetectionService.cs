using AdfsPlugin.Interfaces;
using AdfsPlugin.Models;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace AdfsPlugin.Services
{
    /// <summary>
    /// An additional validation service to invoke an external threat detection service
    /// (dummy Http server)
    /// </summary>
    internal class ExternalThreatDetectionService : IExternalThreatDetectionService
    {
        private readonly HttpClient _httpClient;
        private string _url;

        public ExternalThreatDetectionService()
        {
            _httpClient = new HttpClient();
        }

        /// <summary>
        /// Updates Http Client Configuration with server address and timeout
        /// </summary>
        /// <param name="config">A configuration</param>
        public void UpdateConfiguration(HttpClientConfig config)
        {
            _httpClient.Timeout = TimeSpan.FromSeconds(config.Timeout);
            _url = config.Url;
        }

        /// <summary>
        /// Returns response from an external Http service if to allow to continue authentication process.
        /// Mimics behavior of a dummy service in case of error returning True or False randomly.
        /// </summary>
        /// <returns>True or False</returns>
        public async Task<bool> IsAuthenticationAllowed()
        {
            try
            {
                var response = await _httpClient.GetAsync(_url);
                return Convert.ToBoolean(await response.Content.ReadAsStringAsync());
            }
            catch
            {
                // return false;
                return new Random().Next(2) == 1;
            }
        }
    }
}
