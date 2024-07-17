package main

import (
	"log"
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

	auth := auth.NewAuthenticator(os.Getenv("OPENAI_EMAIL"), os.Getenv("OPENAI_PASSWORD"),
		proxyOption, userAgentOption, auth0OpenAiCookiesOption)
	deviceId := os.Getenv("DEVICE_ID")

	err := auth.FirstRegLogin(deviceId)
	if err != nil {
		panic(err)
	}

	log.Printf("success")
}
