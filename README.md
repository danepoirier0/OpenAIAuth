##### 基于github.com/xqdoo00o/OpenAIAuth, 添加Cookies可以解决部分的403问题,只更新了go代码部分
- 有些特别黑的IP是无法靠请求中添加Cookies来解决的
- 一般情况下 UserAgent、IP是和Cookies绑定的,其中一个变化会造成Cookies无效。
- 有些黑的IP，下层的TCP链接断开后重新链接也会造成Cookies无效
- 特别黑的IP，在正常浏览器中也无法过CloudFlare防护


##### 方法列表
- NewAuthenticator: 用户名密码登录,登录方法是普通的Web登录方式，无法获取长期有效的RefreshToken。使用函数选项模式（Functional options pattern）传递额外参数，包括代理、UserAgent、ChatOpenAiCookies、AuthOpenAiCookies.具体调用可以参考main.go中
- Begin: 运行登录流程(登录完成后就可以通过其它方法获取信息)。 只获取 GetAuthResult.AccessToken字段
- GetPUID: 获取 GetAuthResult.PUID字段。
- GetTeamUserID: 获取 GetAuthResult.TeamUserID 字段.
- GetAuthResult: 获取AccessToken, puid, TeamUserId。PUID只在开通了ChatGPT 4订阅权限下才会获取到。 TeamUserID也可能是在开通了Team后才会获取到
- RenewWithCookies: 刷新AccessToken


##### 其它改进
- 在某些请求中加上sec-ch-ua-arch和sec-ch-ua-bitness能过避免让接口返回403

