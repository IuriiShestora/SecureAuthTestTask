using Microsoft.IdentityServer.Public.ThreatDetectionFramework;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using Newtonsoft.Json;
using System.IO;
using AdfsPlugin.Models;
using AdfsPlugin.Interfaces;
using AdfsPlugin.Services;

namespace AdfsPlugin
{
    /// <summary>
    /// An AD FS Risk Assessment Model Plug-In which is being called on Pre-Authentication Stage.
    /// </summary>
    public class CustomThreatDetectionModule : ThreatDetectionModule, IPreAuthenticationThreatDetectionModule
    {
        private readonly IExternalThreatDetectionService _externalThreatDetectionService;
        private readonly IUserAdStatusService _userAdStatusService;
        private readonly EventLog _eventLog;

        public override string VendorName => "IuriiShestora";
        public override string ModuleIdentifier => "AdfsPlugin.CustomThreatDetectionModule";

        /// <summary>
        /// Default constructor used by AD FS.
        /// </summary>
        public CustomThreatDetectionModule() 
            : this(new ExternalThreatDetectionService(), new UserAdStatusService(), new EventLog())
        {
            if (!EventLog.SourceExists(ModuleIdentifier))
            {
                EventLog.CreateEventSource(ModuleIdentifier, "Application");
            }

            Task.Delay(3000);
            _eventLog.Source = ModuleIdentifier;
        }

        /// <summary>
        /// Parametrized Constructor used by Unit Tests.
        /// </summary>
        /// <param name="externalThreatDetectionService"></param>
        /// <param name="userAdStatusService"></param>
        /// <param name="eventLog"></param>
        public CustomThreatDetectionModule(
            IExternalThreatDetectionService externalThreatDetectionService, 
            IUserAdStatusService userAdStatusService,
            EventLog eventLog)
        {
            _externalThreatDetectionService = externalThreatDetectionService;
            _userAdStatusService = userAdStatusService;
            _eventLog = eventLog;
        }

        /// <summary>
        /// Called when Module is registered in Authentication Pipeline.
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        public override void OnAuthenticationPipelineLoad(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            _externalThreatDetectionService.UpdateConfiguration(
                configData.DataPresent
                ? ParseConfiguration(configData)
                : HttpClientConfig.Default);
        }

        /// <summary>
        /// Called when Authentication Pipeline uploads.
        /// </summary>
        /// <param name="logger"></param>
        public override void OnAuthenticationPipelineUnload(ThreatDetectionLogger logger)
        {
        }

        /// <summary>
        /// Called when Configuration is changed
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData">A text file containing Configuration for HttpClient in JSON format.</param>
        public override void OnConfigurationUpdate(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            _externalThreatDetectionService.UpdateConfiguration(
                configData.DataPresent
                ? ParseConfiguration(configData)
                : HttpClientConfig.Default);
        }

        /// <summary>
        /// Performs additional logic to determine threat conditions and whether to allow authentication process to continue or block it immediately.
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="requestContext"></param>
        /// <param name="securityContext"></param>
        /// <param name="protocolContext"></param>
        /// <param name="additionalClams"></param>
        /// <returns>ThrottleStatus Allow or Block depending on additional logic results.</returns>
        public async Task<ThrottleStatus> EvaluatePreAuthentication(
            ThreatDetectionLogger logger, 
            RequestContext requestContext, 
            SecurityContext securityContext, 
            ProtocolContext protocolContext, 
            IList<Claim> additionalClams)
        {
            var userName = securityContext.UserIdentifier.Split('@')[0];
            var isUserEnabled = _userAdStatusService.IsEnabled(userName);
            
            if(isUserEnabled == null)
            {
                _eventLog?.WriteEntry($"User {securityContext.UserIdentifier} not found in Active Directory.", EventLogEntryType.Information);
                return ThrottleStatus.Block;
            }

            if(isUserEnabled == false)
            {
                _eventLog?.WriteEntry($"User {securityContext.UserIdentifier} is not Enabled in Active Directory.", EventLogEntryType.Information);
                return ThrottleStatus.Block;
            }

            _eventLog?.WriteEntry($"User {securityContext.UserIdentifier} is Enabled in Active Directory.", EventLogEntryType.Information);

            if (!(await _externalThreatDetectionService.IsAuthenticationAllowed()))
            {
                _eventLog?.WriteEntry($"User {securityContext.UserIdentifier} is not Allowed to be Authenticated by Extenal Service.", EventLogEntryType.Information);
                return ThrottleStatus.Block;
            }

            _eventLog?.WriteEntry($"User {securityContext.UserIdentifier} is Allowed to be Authenticated by Extenal Service.", EventLogEntryType.Information);

            return ThrottleStatus.Allow;
        }

        /// <summary>
        /// Parse Configuration or return Default values.
        /// </summary>
        /// <param name="configData"></param>
        /// <returns></returns>
        private HttpClientConfig ParseConfiguration(ThreatDetectionModuleConfiguration configData)
        {
            var serializer = new JsonSerializer();
            try
            {
                using (var sr = new StreamReader(configData.ReadData()))
                using (var jsonTextReader = new JsonTextReader(sr))
                {
                    return serializer.Deserialize<HttpClientConfig>(jsonTextReader);
                }
            }
            catch
            {
                return HttpClientConfig.Default;
            }
        }
    }
}