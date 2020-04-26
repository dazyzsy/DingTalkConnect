# DingTalkConnect
asp.net core 钉钉扫码登录

# 使用方法

```           
              services.AddAuthentication()
                      .AddDingTalk(dingtalkOptions => {
                        dingtalkOptions.AppId = _appConfiguration["App:DingTalkQrLoginAppId"];
                        dingtalkOptions.AppSecret = _appConfiguration["App:DingTalkQrLoginAppSecret"];
                        dingtalkOptions.UseCachedStateDataFormat = true;
                      });
```
