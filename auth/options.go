package auth

import "strings"

type Option func(*UserLogin)

func WithProxy(proxyUrl string) Option {
	return func(ul *UserLogin) {
		ul.client = NewHttpClient(proxyUrl)
	}
}

func WithUserAgent(userAgent string) Option {
	return func(ul *UserLogin) {
		ul.userAgent = userAgent
	}
}

func WithChatGPTCookies(chatGPTCookies map[string]string) Option {
	return func(ul *UserLogin) {

		cookiePairs := []string{}
		for k, v := range chatGPTCookies {
			cookiePairs = append(cookiePairs, k+"="+v)
		}
		cookieStr := strings.Join(cookiePairs, ";")

		ul.chatGPTCookies = cookieStr
	}
}

func WithAuthOpenaiCookies(authOpenAiCookies map[string]string) Option {
	return func(ul *UserLogin) {
		cookiePairs := []string{}
		for k, v := range authOpenAiCookies {
			cookiePairs = append(cookiePairs, k+"="+v)
		}
		cookieStr := strings.Join(cookiePairs, ";")

		ul.authOpenAiCookies = cookieStr
	}
}

func WithAuth0OpenaiCookies(auth0OpenAiCookies map[string]string) Option {
	return func(ul *UserLogin) {

		cookiePairs := []string{}
		for k, v := range auth0OpenAiCookies {
			cookiePairs = append(cookiePairs, k+"="+v)
		}
		cookieStr := strings.Join(cookiePairs, ";")

		ul.auth0OpenAiCookies = cookieStr
	}
}
