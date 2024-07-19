package main

import (
	"log"
	"os"

	"github.com/danepoirier0/OpenAIAuth/auth"
	"github.com/google/uuid"
)

func main() {
	// Option都是可选的，不传递参数为不应用这个参数
	proxyOption := auth.WithProxy(os.Getenv("PROXY"))
	userAgentOption := auth.WithUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	auth0OpenAiCookiesOption := auth.WithAuth0OpenaiCookies(map[string]string{
		// 这里使用你的Cookies替换,Cookies跟IP、UserAgent绑定
		// "__cf_bm":      "xxxx",
		// "cf_clearance": "yyyy",
	})
	// chatOpenAiCookiesOption := auth.WithChatOpenAiCookies(map[string]string{})
	// authOpenAICookiesOption := auth.WithAuthOpenaiCookies(map[string]string{})

	auth := auth.NewAuthenticator("mdywwbafra@hotmail.com", "RgqpVrPt7RgqpVrPt7",
		os.Getenv("CAPSOLVER_API_KEY"), proxyOption, userAgentOption, auth0OpenAiCookiesOption)

	deviceId := uuid.NewString()

	err := auth.FirstRegLogin(deviceId)
	if err != nil {
		panic(err)
	}

	log.Printf("success")
}
