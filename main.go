package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xqdoo00o/OpenAIAuth/auth"
)

func main() {
	proxyOption := auth.WithProxy("http://localhost:7890")
	// userAgentOption := auth.WithUserAgent(os.Getenv("USER_AGENT"))
	// chatOpenAiCookies := auth.WithChatOpenAiCookies(map[string]string{})
	// authOpenAICookies := auth.WithAuthOpenaiCookies(map[string]string{})

	auth := auth.NewAuthenticator(os.Getenv("OPENAI_EMAIL"), os.Getenv("OPENAI_PASSWORD"), proxyOption)
	err := auth.Begin()
	if err != nil {
		println("Error: " + err.Details)
		println("Location: " + err.Location)
		println("Status code: " + fmt.Sprint(err.StatusCode))
		return
	}

	_, err = auth.GetPUID()
	if err != nil {
		println("Error: " + err.Details)
		println("Location: " + err.Location)
		println("Status code: " + fmt.Sprint(err.StatusCode))
		return
	}

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
