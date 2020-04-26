using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public class DingtalkOptions: OAuthOptions
    {
        // snsapi_auth，必填（snsapi_auth用于钉钉容器内获取用户授权）
        public static string LoginScope = "snsapi_login";
        public static string AuthScope = "snsapi_auth";

        public DingtalkOptions()
        {
            CallbackPath = new PathString("/signin-dingtalk");
            AuthorizationEndpoint = DingtalkDefaults.AuthorizationEndpoint;
            AuthorizationEndpoint2 = DingtalkDefaults.AuthorizationEndpoint2;
            TokenEndpoint = DingtalkDefaults.TokenEndpoint;
            UserInformationEndpoint = DingtalkDefaults.UserInformationEndpoint;

            //Scope 表示应用授权作用域。
            Scope.Add(LoginScope);

            //Dingtalk内嵌浏览器Login只需要AuthScope
            Scope2 = new List<string>();
            Scope2.Add(AuthScope);

            //除了openid外，其余的都可能为空，因为Dingtalk获取用户信息是有单独权限的
            ClaimActions.MapJsonKey("sub", "openid");
            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "openid");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "nickname");

            IsDingTalkBrowser = (r) => r.Headers[HeaderNames.UserAgent].ToString().ToLower().Contains("ding");
        }

        public string AppId
        {
            get { return ClientId; }
            set { ClientId = value; }
        }
        /// <summary>
        /// 应用密钥AppSecret，在Dingtalk开放平台提交应用审核通过后获得
        /// </summary>
        public string AppSecret
        {
            get { return ClientSecret; }
            set { ClientSecret = value; }
        }

        /// <summary>
        /// 网站Dingtalk登录有两种场景，一种是在Dingtalk客户端内打开登录，一种是在Dingtalk客户端外登录。
        /// 在Dingtalk内登录直接转到让用户授权页面，在Dingtalk外则为显示二微码让用户扫描后在Dingtalk内授权。
        /// AuthorizationEndpoint是在Dingtalk外登录地址，AuthorizationEndpoint2是Dingtalk内登录地址
        /// </summary>
        public string AuthorizationEndpoint2 { get; set; }

        /// <summary>
        /// Dingtalk内登录第三方网站 的Scope
        /// </summary>
        public ICollection<string> Scope2 { get; set; }

        /// <summary>
        /// 是否是Dingtalk内置浏览器
        /// </summary>
        public Func<HttpRequest, bool> IsDingTalkBrowser { get; set; }

        public bool UseCachedStateDataFormat { get; set; } = false;
    }
}
