package auth

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

func WithChatOpenAiCookies(chatOpenAiCookies map[string]string) Option {
	return func(ul *UserLogin) {
		ul.chatOpenAiCookies = chatOpenAiCookies
	}
}

func WithAuthOpenaiCookies(authOpenAiCookies map[string]string) Option {
	return func(ul *UserLogin) {
		ul.authOpenAiCookies = authOpenAiCookies
	}
}
