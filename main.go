package main

import (
	"log"
	"net/url"
	"os"

	"github.com/danepoirier0/OpenAIAuth/auth"
)

func main() {
	// Option都是可选的，不传递参数为不应用这个参数
	proxyOption := auth.WithProxy(os.Getenv("PROXY"))
	userAgentOption := auth.WithUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0")
	auth0OpenAiCookiesOption := auth.WithAuth0OpenaiCookies(map[string]string{
		// 这里使用你的Cookies替换,Cookies跟IP、UserAgent绑定
		// "__cf_bm":      "xxxx",
		// "cf_clearance": "yyyy",
	})
	// chatOpenAiCookiesOption := auth.WithChatOpenAiCookies(map[string]string{})
	// authOpenAICookiesOption := auth.WithAuthOpenaiCookies(map[string]string{})

	auth := auth.NewAuthenticator("dcanfwph@hotmail.com", "7TQphxTRNq7TQphxTRNq",
		proxyOption, userAgentOption, auth0OpenAiCookiesOption)
	authorizedPage := "https://auth.openai.com/authorize?client_id=TdJIcbe16WoTHtN95nyywh5E4yOo6ItG&scope=openid%20email%20profile%20offline_access%20model.request%20model.read%20organization.read%20organization.write&response_type=code&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Flogin-web&audience=https%3A%2F%2Fapi.openai.com%2Fv1&device_id=df107179-6c75-4f42-8ef1-6c7d9faf802b&prompt=login&screen_hint=login&ext-statsig-tier=production&ext-oai-did=df107179-6c75-4f42-8ef1-6c7d9faf802b&flow=control&state=BDrQSpJdFshNTR_6vAxeHtM7QT3eVC_oCvwCE2W2mZE&code_challenge=B25SYCxcG4a9PPfmfwTL8uuq120lVXs42QPPE6QVuw8&code_challenge_method=S256"
	parsedAuthPage, err := url.Parse(authorizedPage)
	if err != nil {
		panic(err)
	}
	deviceId := parsedAuthPage.Query().Get("device_id")

	err = auth.FirstRegLogin(authorizedPage, deviceId)
	if err != nil {
		panic(err)
	}

	log.Printf("success")
}
