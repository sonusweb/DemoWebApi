using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace ContactManager.Filters
{
    public class HMACAuthenticationAttribute :Attribute, IAuthenticationFilter
    {
        private readonly string authenticationScheme = "amx";
        UInt64 requestMaxAgeInSeconds = Convert.ToUInt64(ConfigurationManager.AppSettings["hmacrequesttime"]);// 300;

        public HMACAuthenticationAttribute()
        {
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;

            if (req.Headers.Authorization != null && authenticationScheme.Equals(req.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                var rawAuthzHeader = req.Headers.Authorization.Parameter;
                var autherizationHeaderArray = GetAutherizationHeaderValues(rawAuthzHeader);

                if (autherizationHeaderArray != null)
                {
                    var partnerKey = autherizationHeaderArray[0];
                    var clientKey = autherizationHeaderArray[1];
                    var APPId = partnerKey + clientKey;
                    var incomingBase64Signature = autherizationHeaderArray[2];
                    var nonce = autherizationHeaderArray[3];
                    var requestTimeStamp = autherizationHeaderArray[4];

                    var secType = ConfigurationManager.AppSettings[clientKey + "SecurityType"];

                    if (secType == "hmac")
                    {
                        var isValid = isValidRequest(req, partnerKey, clientKey, incomingBase64Signature, nonce, requestTimeStamp);

                        if (isValid.Result)
                        {
                            var currentPrincipal = new GenericPrincipal(new GenericIdentity(APPId), null);
                            context.Principal = currentPrincipal;
                        }
                        else
                        {
                            context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                        }
                    }
                    else { }
                }
                else
                {
                    context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                }
            }
            else
            {
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }

            return Task.FromResult(0);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result);
            return Task.FromResult(0);
        }

        public bool AllowMultiple
        {
            get { return false; }
        }
        /// <summary>
        /// Split the authorization header with ':' separator and return as array value 
        /// </summary>
        /// <param name="rawAuthzHeader">Authorization header value</param>
        /// <returns><see cref="string[]"/></returns>

        private string[] GetAutherizationHeaderValues(string rawAuthzHeader)
        {
            var credArray = rawAuthzHeader.Split(':');

            if (credArray.Length == 5)
            {
                return credArray;
            }
            else
            {
                return null;
            }
        }

        private async Task<bool> isValidRequest(HttpRequestMessage req, string partnerKey, string clientKey, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            var APPId = partnerKey + clientKey;

            if (ConfigurationManager.AppSettings[clientKey + "AppId"].ToString() != APPId)
            {
                return false;
            }

            var sharedKey = ConfigurationManager.AppSettings[clientKey + "Secret"];

            if (isReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }

            byte[] hash = await ComputeHash(req.Content);
            //if (hash != null)
            //{
            //    requestContentBase64String = Convert.ToBase64String(hash);
            //}

            string data = String.Format("{0}{1}{2}{3}", sharedKey, APPId, requestTimeStamp, nonce);

            //var secretKeyBytes = Convert.FromBase64String(sharedKey);
            //byte[] signature = Encoding.UTF8.GetBytes(data);
            //using (HMACSHA256 hmac = new HMACSHA256(secretKeyBytes))
            //{
            //    byte[] signatureBytes = hmac.ComputeHash(signature);
            //    return (incomingBase64Signature.Equals(Convert.ToBase64String(signatureBytes), StringComparison.Ordinal));
            //}

            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(sharedKey);
            byte[] messageBytes = encoding.GetBytes(data);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                // var getRsult = (incomingBase64Signature.Equals(Convert.ToBase64String(hashmessage), StringComparison.Ordinal));
                return (incomingBase64Signature.Equals(Convert.ToBase64String(hashmessage), StringComparison.Ordinal));
            }

        }

        private bool isReplayRequest(string nonce, string requestTimeStamp)
        {
            if (System.Runtime.Caching.MemoryCache.Default.Contains(nonce))
            {
                return true;
            }

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToUInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToUInt64(requestTimeStamp);

            if ((serverTotalSeconds - requestTotalSeconds) > requestMaxAgeInSeconds)
            {
                return true;
            }

            System.Runtime.Caching.MemoryCache.Default.Add(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(requestMaxAgeInSeconds));

            return false;
        }

        private static async Task<byte[]> ComputeHash(HttpContent httpContent)
        {
            //using (MD5 md5 = MD5.Create())
            //{
            byte[] hash = null;
            var content = await httpContent.ReadAsByteArrayAsync();
            //if (content.Length != 0)
            //{
            //    hash = md5.ComputeHash(content);
            //}
            return hash;
            //}
        }
    }
    public class ResultWithChallenge : IHttpActionResult
    {
        private readonly string authenticationScheme = "amx";
        private readonly IHttpActionResult next;

        public ResultWithChallenge(IHttpActionResult next)
        {
            this.next = next;
        }

        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var response = await next.ExecuteAsync(cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(authenticationScheme));
            }

            return response;
        }
    }
}