using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace Host.Quickstart.Account
{
    [ApiController]
    [Authorize]
    [Route("[controller]")]
    public class SessionController : ControllerBase
    {
        private readonly AppSessionStoreService _appSessionStore;
        public SessionController(AppSessionStoreService appSessionStore)
        {
            _appSessionStore = appSessionStore ?? throw new ArgumentNullException(nameof(appSessionStore));
        }

        [HttpPost]
        public IActionResult Post(CreateAppSessionDto data)
        {
            var otp = _appSessionStore.Add(data);
            return Ok(new { Otp = otp });
        }

        [HttpGet]
        [AllowAnonymous]
        [EnableCors("anonymous")]
        public IActionResult Get(int otp)
        {
            return Ok(_appSessionStore.Get(otp));
        }
    }

    public class AppSessionStoreService : IDisposable
    {
        // Key: OPT, Value: CreateAppSessionDto request
        private static readonly ConcurrentDictionary<int, CreateAppSessionDto> AppSessionStore = new ConcurrentDictionary<int, CreateAppSessionDto>();
        // Key: yyyyMMddHHmm (expiry time), Value: _appSessionStore.Key <!
        private static readonly ConcurrentDictionary<long, HashSet<int>> AppSessionKeyStore = new ConcurrentDictionary<long, HashSet<int>>();
        private static readonly Random OptGenerator = new Random();
        public const int MaxSessionExpiryInMins = 1;

        public long Add(CreateAppSessionDto value)
        {
            // OTP should be unique
            var otp = GetNewOtp();

            while (!AppSessionStore.TryAdd(otp, value))
                otp = GetNewOtp();

            if (!AppSessionKeyStore.TryGetValue(value.ExpiryKey, out var keys))
                keys = new HashSet<int>();

            if (!keys.Contains(otp)) keys.Add(otp);

            AppSessionKeyStore[value.ExpiryKey] = keys;

            return otp;
        }

        public CreateAppSessionDto Get(int otp)
        {
            AppSessionStore.TryRemove(otp, out var result);
            AppSessionKeyStore.TryRemove(result?.ExpiryKey ?? 0, out _);

            return !(result?.Expired ?? true) ? result : default;
        }

        private static int GetNewOtp() => OptGenerator.Next(100000, 999999);

        private static void RemoveExpiredSessions()
        {
            var topExpiryKey = long.Parse(DateTime.UtcNow.ToString("yyyyMMddHHmm"));
            var expiredSessions = AppSessionKeyStore.Where(item => item.Key <= topExpiryKey);

            if (!expiredSessions.Any()) return;

            expiredSessions.ToList()
                .ForEach(session =>
                {
                    foreach (var key in session.Value)
                        AppSessionStore.TryRemove(key, out _);

                    AppSessionKeyStore.TryRemove(session.Key, out _);
                });
        }

        private bool _disposedValue;
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    // free managed resources (managed objects)
                    RemoveExpiredSessions();
                }

                // free unmanaged resources (unmanaged objects)
                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public sealed class CreateAppSessionDto
    {
        [JsonPropertyName("client_id")]
        public string ClientId { get; set; }
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonIgnore]
        internal DateTime Expiry { get; }
        [JsonIgnore]
        internal long ExpiryKey => long.Parse(Expiry.ToString("yyyyMMddHHmm"));
        [JsonIgnore]
        internal bool Expired => Expiry < DateTime.UtcNow;

        public CreateAppSessionDto()
        {
            Expiry = DateTime.UtcNow.AddMinutes(AppSessionStoreService.MaxSessionExpiryInMins);
        }
    }
}
