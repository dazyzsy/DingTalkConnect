using DingTalk.Api;
using DingTalk.Api.Request;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;


namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public class DingtalkHandler : OAuthHandler<DingtalkOptions>
    {
        private readonly ISecureDataFormat<AuthenticationProperties> _secureDataFormat;
        protected override async Task InitializeHandlerAsync()
        {
            await base.InitializeHandlerAsync();
            if (Options.UseCachedStateDataFormat)
            {
                Options.StateDataFormat = _secureDataFormat;
            }
        }

        public DingtalkHandler(
             IOptionsMonitor<DingtalkOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISecureDataFormat<AuthenticationProperties> secureDataFormat
  )
            : base(options, logger, encoder, clock)
        {
            _secureDataFormat = secureDataFormat;
        }
        /*
         * Challenge 盘问握手认证协议
         * 这个词有点偏，好多翻译工具都查不出。
         * 这个解释才是有些靠谱 http://abbr.dict.cn/Challenge/CHAP
         */
        /// <summary>
        /// 构建请求CODE的Url地址（这是第一步，准备工作）
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var scope = FormatScope();

            var state = Options.StateDataFormat.Protect(properties);

            var parameters = new Dictionary<string, string>()
            {
                { "appid", Options.ClientId },
                { "redirect_uri", redirectUri },
                { "response_type", "code" },
            };

            // 判断当前请求是否由Dingtalk内置浏览器发出
            var IsDingTalkBrowser = Options.IsDingTalkBrowser(Request);
            var ret = QueryHelpers.AddQueryString(
                IsDingTalkBrowser ? Options.AuthorizationEndpoint2
                    : Options.AuthorizationEndpoint, parameters);
            // scope 不能被UrlEncode
            ret += $"&scope={scope}&state={state}";

            return ret;
        }

        /// <summary>
        /// 处理Dingtalk授权结果（接收Dingtalk授权的回调）
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            //第一步，处理工作
            AuthenticationProperties properties = null;
            var query = Request.Query;

            //Dingtalk只会发送code和state两个参数，不会返回错误消息
            //若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
            var code = query["code"];
            var state = query["state"];

            properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }
          
            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.");
            }

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.");
            }
            OAuthCodeExchangeContext ctx = new OAuthCodeExchangeContext(null, code, BuildRedirectUri(Options.CallbackPath));

            //第二步，通过Code获取Access Token
            var tokens = await ExchangeCodeAsync(ctx);
            // var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error);
            }

            var resStr = tokens.Response.RootElement.GetRawText();
            if (string.IsNullOrEmpty(resStr))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType)) //Dingtalk就没有这个
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }

            DefaultDingTalkClient client = new DefaultDingTalkClient("https://oapi.dingtalk.com/sns/getuserinfo_bycode");
            OapiSnsGetuserinfoBycodeRequest req = new OapiSnsGetuserinfoBycodeRequest();
            req.TmpAuthCode = code;
            var response = client.Execute(req, Options.AppId, Options.AppSecret);

            //获取OpenId
            if (response.IsError)
            {
                return HandleRequestResult.Fail(response.Errmsg);
            }

            identity.AddClaim(new Claim("sub", response.UserInfo.Openid, ClaimValueTypes.String, ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, response.UserInfo.Openid, ClaimValueTypes.String, ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.Name, response.UserInfo.Nick, ClaimValueTypes.String, ClaimsIssuer));
            identity.AddClaim(new Claim("urn:dingtalk:openid", response.UserInfo.Openid, ClaimValueTypes.String, ClaimsIssuer));
            identity.AddClaim(new Claim("urn:dingtalk:unionid", response.UserInfo.Unionid, ClaimValueTypes.String, ClaimsIssuer));

            var jsonString = JsonSerializer.Serialize(response.UserInfo);

            var payload = JsonDocument.Parse(jsonString);
            tokens = OAuthTokenResponse.Success(payload);

            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.");
            }
        }

        /// <summary>
        /// Dingtalk中不需要用Code换取AccessToken,类似直接拿Code当AccessToken用，但是一次性的
        /// </summary>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            var jsonString = JsonSerializer.Serialize(new { AccessToken = context.Code });

            var payload = JsonDocument.Parse(jsonString);
            var res = OAuthTokenResponse.Success(payload);
            return await Task.FromResult(res);

        }

        /// <summary>
        /// 创建身份票据(这是第三步) 
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="properties"></param>
        /// <param name="tokens"></param>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {
            // 不访问 getuser 接口获取其它用户信息了
            var userInfo = tokens.Response.RootElement;

            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, userInfo);
            context.RunClaimActions();
            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        /// <summary>
        /// 根据是否为Dingtalk浏览器返回不同Scope
        /// </summary>
        /// <returns></returns>
        protected override string FormatScope()
        {
            if (Options.IsDingTalkBrowser(Request))
            {
                return string.Join(",", Options.Scope2);
            }
            else
            {
                return string.Join(",", Options.Scope);
            }

        }
    }
}
