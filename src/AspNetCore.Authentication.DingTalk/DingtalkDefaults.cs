namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public static class DingtalkDefaults
    {
        public const string AuthenticationScheme = "DingTalk";

        public static readonly string DisplayName = "DingTalk";

        //https://oapi.dingtalk.com/connect/qrconnect?appid=APPID&response_type=code&scope=snsapi_login&state=STATE&redirect_uri=REDIRECT_URI
        /// <summary>
        /// 第一步，获取授权临时票据（code）地址，适用于钉钉客户端外的网页登录
        /// </summary>
        public static readonly string AuthorizationEndpoint = "https://oapi.dingtalk.com/connect/qrconnect";

        /// <summary>
        /// 第一步，获取授权临时票据（code）地址，适用于钉钉客户端内的网页登录（在钉钉内部访问登录）
        /// </summary>
        public static readonly string AuthorizationEndpoint2 = "https://oapi.dingtalk.com/connect/oauth2/sns_authorize";

        ///// <summary>
        ///// 第二步，用户允许授权后，通过返回的code换取access_token地址
        ///// </summary>
        public static readonly string TokenEndpoint = "https://oapi.dingtalk.com/sns/oauth2/access_token";

        /// <summary>
        /// 第三步，使用code获取用户个人信息地址
        /// </summary>
        public static readonly string UserInformationEndpoint = "https://oapi.dingtalk.com/sns/getuserinfo_bycode";
    }
}
