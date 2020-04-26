using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;


namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public static class DingtalkExtensions
    {
        public static AuthenticationBuilder AddDingTalk(this AuthenticationBuilder builder)
            => builder.AddDingTalk(DingtalkDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddDingTalk(this AuthenticationBuilder builder, Action<DingtalkOptions> configureOptions)
            => builder.AddDingTalk(DingtalkDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddDingTalk(this AuthenticationBuilder builder, string authenticationScheme, Action<DingtalkOptions> configureOptions)
            => builder.AddDingTalk(authenticationScheme, DingtalkDefaults.DisplayName, configureOptions);


        public static AuthenticationBuilder AddDingTalk(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<DingtalkOptions> configureOptions)
        {

            builder.Services.TryAddTransient<ISecureDataFormat<AuthenticationProperties>>((provider) =>
            {
                var dataProtectionProvider = provider.GetRequiredService<IDataProtectionProvider>();
                var distributedCache = provider.GetRequiredService<IDistributedCache>();

                var dataProtector = dataProtectionProvider.CreateProtector(
                    typeof(DingtalkHandler).FullName,
                    typeof(string).FullName, DingtalkDefaults.AuthenticationScheme,
                    "v1");

                var dataFormat = new CachedPropertiesDataFormat(distributedCache, dataProtector);
                return dataFormat;
            });


            return builder.AddOAuth<DingtalkOptions, DingtalkHandler>(authenticationScheme,
                displayName, configureOptions);
        }


    }
}
