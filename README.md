##### 基于github.com/xqdoo00o/OpenAIAuth, 添加Cookies可以解决部分的403问题,只更新了go代码部分
- 有些特别黑的IP是无法靠请求中添加Cookies来解决的
- 一般情况下 UserAgent、IP是和Cookies绑定的,其中一个变化会造成Cookies无效。
- 有些黑的IP，下层的TCP链接断开后重新链接也会造成Cookies无效
- 特别黑的IP，在正常浏览器中也无法过CloudFlare防护

##### 方法列表
- NewAuthenticator: 用户名密码登录,登录方法是普通的Web登录方式，无法获取长期有效的RefreshToken。使用函数选项模式（Functional options pattern）传递额外参数，包括代理、UserAgent、ChatOpenAiCookies、AuthOpenAiCookies、Auth0OpenAiCookies.具体调用可以参考main.go中
- Begin: 运行登录流程(登录完成后就可以通过其它方法获取信息)。 只获取 GetAuthResult.AccessToken字段
- GetPUID: 获取 GetAuthResult.PUID字段。
- GetTeamUserID: 获取 GetAuthResult.TeamUserID 字段.
- GetAuthResult: 获取AccessToken, puid, TeamUserId。PUID只在开通了ChatGPT 4订阅权限下才会获取到。 TeamUserID也可能是在开通了Team后才会获取到
- RenewWithCookies: 刷新AccessToken

##### 如何获取登录har
- 计算Arkose值，有两种方式，一种是自己或者登录har放到harPool中，另一种方式是使用计算Arkose的平台（在本项目中使用WithLoginArkosePlatform方法设置）。
- 获取的har是登录的har文件，不是聊天的har。流程可以参考聊天har的获取方式[参考这里](https://github.com/gngpp/ninja/wiki/2-Arkose)
- 走登录流程，要保存har文件的链接是```https://tcr9i.openai.com/fc/gt2/public_key/0A1D34FC-659D-4E23-B17B-694DCFCF6A6C```
- har包含浏览器指纹，多次使用后可能会跟IP一样出现不能使用的问题，不能使用后需要更换。或者多放几个不同浏览器或者不同浏览器版本的har进去


##### 如何获取过CloudFlare盾的cookie
- 可以联系我们解决
- 或者自己复制自己过了CloudFlare盾后的Cookie
- 或者自己编写过盾程序,但目前puppeteer、playwright都能被检测到，不管是否是开启了UI界面