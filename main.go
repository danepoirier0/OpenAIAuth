package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xqdoo00o/OpenAIAuth/auth"
)

func main() {
	// Option都是可选的，不传递参数为不应用这个参数
	proxyOption := auth.WithProxy(os.Getenv("PROXY"))
	userAgentOption := auth.WithUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	auth0OpenAiCookiesOption := auth.WithAuth0OpenaiCookies(map[string]string{
		// 这里使用你的Cookies替换,Cookies跟IP、UserAgent绑定
		// "__cf_bm":      "xxxx",
		// "cf_clearance": "yyyy",
	})
	// chatOpenAiCookiesOption := auth.WithChatOpenAiCookies(map[string]string{})
	// authOpenAICookiesOption := auth.WithAuthOpenaiCookies(map[string]string{})

	auth := auth.NewAuthenticator(os.Getenv("OPENAI_EMAIL"), os.Getenv("OPENAI_PASSWORD"),
		proxyOption, userAgentOption, auth0OpenAiCookiesOption)
	err := auth.Begin()
	if err != nil {
		println("Error: " + err.Details)
		println("Location: " + err.Location)
		println("Status code: " + fmt.Sprint(err.StatusCode))
		return
	}

	// _, err = auth.GetPUID()
	// if err != nil {
	// 	println("Error: " + err.Details)
	// 	println("Location: " + err.Location)
	// 	println("Status code: " + fmt.Sprint(err.StatusCode))
	// 	return
	// }

	// _, err = auth.GetTeamUserID()
	// if err != nil {
	// 	println("Error: " + err.Details)
	// 	println("Location: " + err.Location)
	// 	println("Status code: " + fmt.Sprint(err.StatusCode))
	// 	return
	// }

	// JSON encode auth.GetAuthResult()
	result := auth.GetAuthResult()
	result_json, _ := json.Marshal(result)
	println(string(result_json))
}
