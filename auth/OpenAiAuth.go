package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/danepoirier0/funcaptcha"
	arkose "github.com/danepoirier0/funcaptcha"
)

type Error struct {
	Location   string
	StatusCode int
	Details    string
}

func NewError(location string, statusCode int, details string) *Error {
	return &Error{
		Location:   location,
		StatusCode: statusCode,
		Details:    details,
	}
}

type AccountCookies map[string][]*http.Cookie

var allCookies AccountCookies

type Result struct {
	AuthCookies []*http.Cookie `json:"auth_cookies"`
	AccessToken string         `json:"access_token"`
	PUID        string         `json:"puid"`
	TeamUserID  string         `json:"team_uid,omitempty"`
}

const (
	defaultErrorMessageKey             = "errorMessage"
	AuthorizationHeader                = "Authorization"
	XAuthorizationHeader               = "X-Authorization"
	ContentType                        = "application/x-www-form-urlencoded"
	UserAgent                          = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	Auth0Url                           = "https://auth0.openai.com"
	LoginUsernameUrl                   = Auth0Url + "/u/login/identifier?state="
	LoginPasswordUrl                   = Auth0Url + "/u/login/password?state="
	ParseUserInfoErrorMessage          = "Failed to parse user login info."
	GetAuthorizedUrlErrorMessage       = "Failed to get authorized url."
	GetStateErrorMessage               = "Failed to get state."
	EmailInvalidErrorMessage           = "Email is not valid."
	EmailOrPasswordInvalidErrorMessage = "Email or password is not correct."
	GetAccessTokenErrorMessage         = "Failed to get access token."
	GetArkoseTokenErrorMessage         = "Failed to get arkose token."
	defaultTimeoutSeconds              = 600 // 10 minutes

	csrfUrl                  = "https://chatgpt.com/api/auth/csrf"
	promptLoginUrl           = "https://chatgpt.com/api/auth/signin/login-web?prompt=login"
	getCsrfTokenErrorMessage = "Failed to get CSRF token."
	authSessionUrl           = "https://chatgpt.com/api/auth/session"
)

type UserLogin struct {
	Username           string
	Password           string
	client             tls_client.HttpClient
	Result             Result
	userAgent          string
	chatGPTCookies     string // chatgpt.com 需要的Cookies
	authOpenAiCookies  string // auth.openai.com 需要的Cookies
	auth0OpenAiCookies string // auth0.openai.com 需要的Cookies
}

//goland:noinspection GoUnhandledErrorResult,SpellCheckingInspection
func NewHttpClient(proxyUrl string) tls_client.HttpClient {
	client := getHttpClient()

	if proxyUrl != "" {
		client.SetProxy(proxyUrl)
	}

	return client
}

func getHttpClient() tls_client.HttpClient {
	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithTimeoutSeconds(600),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}...)
	return client
}

func NewAuthenticator(emailAddress, password string, opts ...Option) *UserLogin {
	userLogin := &UserLogin{
		Username:           emailAddress,
		Password:           password,
		client:             NewHttpClient(""),
		userAgent:          UserAgent,
		chatGPTCookies:     "",
		authOpenAiCookies:  "",
		auth0OpenAiCookies: "",
	}

	for _, opt := range opts {
		opt(userLogin)
	}

	return userLogin
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetAuthorizedUrl(csrfToken string) (string, int, error) {
	form := url.Values{
		"callbackUrl": {"/"},
		"csrfToken":   {csrfToken},
		"json":        {"true"},
	}
	req, err := http.NewRequest(http.MethodPost, promptLoginUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", userLogin.userAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, errors.New(GetAuthorizedUrlErrorMessage)
	}

	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	return responseMap["url"], http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetState(authorizedUrl string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, authorizedUrl, nil)

	req.Header.Set("User-Agent", userLogin.userAgent)
	// req.Header.Set("sec-ch-ua-arch", "x86")
	// req.Header.Set("sec-ch-ua-bitness", "64")

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return resp.StatusCode, errors.New(NewCloudFlare403ErrorMessage(authorizedUrl))
		} else {
			errMsg := fmt.Sprintf("url %s return status code %d", authorizedUrl, resp.StatusCode)
			return resp.StatusCode, errors.New(errMsg)
		}

	}
	return http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckUsername(authorizedUrl string, username string) (string, string, int, error) {
	u, _ := url.Parse(authorizedUrl)
	query := u.Query()
	query.Del("prompt")
	query.Set("login_hint", username)
	req, _ := http.NewRequest(http.MethodGet, Auth0Url+"/authorize?"+query.Encode(), nil)

	req.Header.Set("User-Agent", userLogin.userAgent)
	req.Header.Set("Referer", "https://auth.openai.com/")
	req.Header.Set("sec-ch-ua-arch", "x86")
	req.Header.Set("sec-ch-ua-bitness", "64")
	req.Header.Set("Cookie", userLogin.auth0OpenAiCookies)

	userLogin.client.SetFollowRedirect(false)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		redir := resp.Header.Get("Location")
		req, _ := http.NewRequest(http.MethodGet, Auth0Url+redir, nil)

		req.Header.Set("User-Agent", userLogin.userAgent)
		req.Header.Set("Referer", "https://auth.openai.com/")
		req.Header.Set("Cookie", userLogin.auth0OpenAiCookies)

		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", "", http.StatusInternalServerError, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", "", http.StatusInternalServerError, err
		}
		var dx string
		re := regexp.MustCompile(`blob: "([^"]+?)"`)
		matches := re.FindStringSubmatch(string(body))
		if len(matches) > 1 {
			dx = matches[1]
		}
		u, _ := url.Parse(redir)
		state := u.Query().Get("state")
		return state, dx, http.StatusOK, nil
	} else {
		if resp.StatusCode == http.StatusForbidden {
			return "", "", resp.StatusCode, errors.New(NewCloudFlare403ErrorMessage(Auth0Url + "/authorize?" + query.Encode()))
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", resp.StatusCode, errors.New(string(bodyBytes))
	}
}

func (userLogin *UserLogin) setArkose(dx string) (int, error) {
	token, err := arkose.GetOpenAIAuthToken("", dx, userLogin.client.GetProxy())
	if err == nil {
		u, _ := url.Parse("https://openai.com")
		cookies := []*http.Cookie{}
		userLogin.client.GetCookieJar().SetCookies(u, append(cookies, &http.Cookie{Name: "arkoseToken", Value: token}))
		return http.StatusOK, nil
	} else {
		println("Error getting auth Arkose token")
		return http.StatusInternalServerError, err
	}
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckPassword(state string, username string, password string) (string, int, error) {
	formParams := url.Values{
		"state":    {state},
		"username": {username},
		"password": {password},
	}
	req, err := http.NewRequest(http.MethodPost, LoginPasswordUrl+state, strings.NewReader(formParams.Encode()))

	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", userLogin.userAgent)
	req.Header.Set("sec-ch-ua-arch", "x86")
	req.Header.Set("sec-ch-ua-bitness", "64")
	req.Header.Set("Cookie", userLogin.auth0OpenAiCookies)

	userLogin.client.SetFollowRedirect(false)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}

	if resp.StatusCode == http.StatusForbidden {
		return "", resp.StatusCode, errors.New(NewCloudFlare403ErrorMessage(LoginPasswordUrl + state))
	}

	if resp.StatusCode == http.StatusFound {
		req, _ := http.NewRequest(http.MethodGet, Auth0Url+resp.Header.Get("Location"), nil)

		req.Header.Set("User-Agent", userLogin.userAgent)
		req.Header.Set("Cookie", userLogin.auth0OpenAiCookies)

		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusFound {
			return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
		}

		if resp.StatusCode == http.StatusForbidden {
			return "", resp.StatusCode, errors.New(NewCloudFlare403ErrorMessage(Auth0Url + resp.Header.Get("Location")))
		}

		// resp.StatusCode == http.StatusFound
		// location https://chatgpt.com/api/auth/callback/login-web?code=Q5D8XfC3T2ahbKKDzEevDX5-BDqGA6ZQP4uq8_AXZJyf9&state=uXsYQHYR-3vsM0miDp360l_m8f67tNtHQoRH0otA5YU
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, "/u/mfa-otp-challenge") {
			return "", http.StatusBadRequest, errors.New("Login with two-factor authentication enabled is not supported currently.")
		}

		req, _ = http.NewRequest(http.MethodGet, location, nil)

		req.Header.Set("User-Agent", userLogin.userAgent)

		resp, err = userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		defer resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			log.Println("location xxxxx yyyyy zzzzzz ----  ", location)
			return "", http.StatusOK, nil
		}

		if resp.StatusCode == http.StatusTemporaryRedirect {
			errorDescription := req.URL.Query().Get("error_description")
			if errorDescription != "" {
				return "", resp.StatusCode, errors.New(errorDescription)
			}
		}

		return "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
	}

	return "", resp.StatusCode, nil
}

// //goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat,GoUnusedParameter
// func (userLogin *UserLogin) GetAccessTokenInternal(code string) (string, int, error) {
// 	req, err := http.NewRequest(http.MethodGet, authSessionUrl, nil)
// 	req.Header.Set("User-Agent", userLogin.userAgent)
// 	resp, err := userLogin.client.Do(req)
// 	if err != nil {
// 		return "", http.StatusInternalServerError, err
// 	}

// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		if resp.StatusCode == http.StatusTooManyRequests {
// 			responseMap := make(map[string]string)
// 			json.NewDecoder(resp.Body).Decode(&responseMap)
// 			return "", resp.StatusCode, errors.New(responseMap["detail"])
// 		}

// 		bdBytes, _ := io.ReadAll(resp.Body)
// 		log.Println("resp.StatusCode", resp.StatusCode)
// 		log.Println("bdBytes", string(bdBytes))

// 		return "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
// 	}
// 	var result map[string]interface{}
// 	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
// 		return "", 0, err
// 	}
// 	// Check if access token in data
// 	if _, ok := result["accessToken"]; !ok {
// 		result_string := fmt.Sprintf("%v", result)
// 		return result_string, 0, errors.New("missing access token")
// 	}
// 	return result["accessToken"].(string), http.StatusOK, nil
// }

func (userLogin *UserLogin) Begin() *Error {
	statusCode, err, authCookies := userLogin.GetAuthCookies()
	if err != "" {
		return NewError("begin", statusCode, err)
	}
	userLogin.Result.AuthCookies = authCookies
	return nil
}

// 注册并 Verfiy Email之后, 首次登录调用这个方法
//
// chatGPTAuthLoginPage 为点击 Login 之后的 形如 auth.openai.com/authorize?client_id=xxx 的页面
func (userLogin *UserLogin) FirstRegLogin(chatGPTAuthorizedPage, deviceId string) error {
	// 前1-5步跟普通登录一样，第6步接口一样但是302跳转之后就开始不一样
	// 之后再调用其它的完成注册使用的方法

	// // 1. get csrf token
	// req, _ := http.NewRequest(http.MethodGet, csrfUrl, nil)
	// req.Header.Set("User-Agent", userLogin.userAgent)
	// resp, err := userLogin.client.Do(req)
	// if err != nil {
	// 	return err
	// }
	// defer resp.Body.Close()
	// if resp.StatusCode != http.StatusOK {
	// 	return fmt.Errorf("get %s response code is %d", csrfUrl, resp.StatusCode)
	// }

	// // 2. get authorized url
	// responseMap := make(map[string]string)
	// json.NewDecoder(resp.Body).Decode(&responseMap)
	// authorizedUrl, statusCode, err := userLogin.GetAuthorizedUrl(responseMap["csrfToken"])
	// if err != nil {
	// 	return err
	// }
	// if statusCode != http.StatusOK {
	// 	return fmt.Errorf("GetAuthorizedUrl response code is %d", resp.StatusCode)
	// }

	// // 3. get state
	// statusCode, err := userLogin.GetState(chatGPTAuthorizedPage)
	// if err != nil {
	// 	return err
	// }
	// if statusCode != http.StatusOK {
	// 	return fmt.Errorf("get %s response code is %d", chatGPTAuthorizedPage, statusCode)
	// }

	// 4. check username
	state, dx, statusCode, err := userLogin.CheckUsername(chatGPTAuthorizedPage, userLogin.Username)
	if err != nil {
		return err
	}
	log.Println(" CheckUsername statusCode" + strconv.Itoa(statusCode))

	log.Println("before 5")
	// 5. set arkose captcha
	statusCode, err = userLogin.setArkose(dx)
	if err != nil {
		return err
	}

	log.Println("before 6")
	// 6. check password
	_, statusCode, err = userLogin.CheckPassword(state, userLogin.Username, userLogin.Password)
	if err != nil {
		return err
	}

	// 生成codeverifer和codeChallenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return err
	}
	codeChallenge, err := generateCodeChallenge(codeVerifier)
	if err != nil {
		return err
	}

	log.Println("before 7")

	// 7.
	cbCode, err := userLogin.GetFirstLoginCbCode(deviceId, state, codeChallenge)
	if err != nil {
		return err
	}

	log.Println("before 8")
	// 8.
	accessToken, err := userLogin.GetFirstLoginToken(cbCode, codeVerifier)
	if err != nil {
		return err
	}

	log.Println("before 9")

	// 9.
	arkosePayload, err := userLogin.GetFirstLoginArkosePayload(accessToken)
	if err != nil {
		return err
	}

	log.Println("before 10")
	// 10.
	arkoseToken, err := userLogin.GetFirstLoginInitArkoseToken(arkosePayload)
	if err != nil {
		return err
	}

	log.Println("before 11")
	// 11.
	err = userLogin.FirstLoginSubmitAccountInfo(userLogin.Username, accessToken, arkoseToken)
	if err != nil {
		return err
	}

	return nil
}

func (userLogin *UserLogin) GetAuthCookies() (int, string, []*http.Cookie) {
	// get csrf token
	req, _ := http.NewRequest(http.MethodGet, csrfUrl, nil)

	req.Header.Set("User-Agent", userLogin.userAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err.Error(), nil
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, getCsrfTokenErrorMessage, nil
	}

	// get authorized url
	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	authorizedUrl, statusCode, err := userLogin.GetAuthorizedUrl(responseMap["csrfToken"])
	if err != nil {
		return statusCode, err.Error(), nil
	}

	// get state
	statusCode, err = userLogin.GetState(authorizedUrl)
	if err != nil {
		return statusCode, err.Error(), nil
	}

	// check username
	state, dx, statusCode, err := userLogin.CheckUsername(authorizedUrl, userLogin.Username)
	if err != nil {
		return statusCode, err.Error(), nil
	}

	// set arkose captcha
	statusCode, err = userLogin.setArkose(dx)
	if err != nil {
		return statusCode, err.Error(), nil
	}

	// check password
	_, statusCode, err = userLogin.CheckPassword(state, userLogin.Username, userLogin.Password)
	if err != nil {
		return statusCode, err.Error(), nil
	}

	// // get access token
	// accessToken, statusCode, err := userLogin.GetAccessTokenInternal("")
	// if err != nil {
	// 	return statusCode, err.Error(), ""
	// }

	chatgptUrl, err := url.Parse("https://chatgpt.com")
	if err != nil {
		return -1, err.Error(), nil
	}

	return http.StatusOK, "", userLogin.client.GetCookies(chatgptUrl)
}

func (userLogin *UserLogin) GetAccessToken() string {
	return userLogin.Result.AccessToken
}

func (userLogin *UserLogin) GetPUID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_puid", 0, "Missing access token")
	}
	// Make request to https://chatgpt.com/backend-api/models
	req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/models?history_and_training_disabled=false", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_puid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_puid", resp.StatusCode, "Failed to make request")
	}
	// Find `_puid` cookie in response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_puid" {
			userLogin.Result.PUID = cookie.Value
			return cookie.Value, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_puid", 0, "PUID cookie not found")
}

type UserID struct {
	AccountOrdering []string `json:"account_ordering"`
}

func (userLogin *UserLogin) GetTeamUserID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_teamuserid", 0, "Missing access token")
	}
	req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_teamuserid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_teamuserid", resp.StatusCode, "Failed to make request")
	}

	var userId UserID
	err = json.NewDecoder(resp.Body).Decode(&userId)
	if err != nil {
		return "", NewError("get_teamuserid", 0, "teamuserid not found")
	}
	if len(userId.AccountOrdering) > 1 {
		userLogin.Result.TeamUserID = userId.AccountOrdering[0]
		return userId.AccountOrdering[0], nil
	}
	// If cookie not found, return error
	return "", NewError("get_teamuserid", 0, "teamuserid not found")
}

func init() {
	allCookies = AccountCookies{}
	file, err := os.Open("cookies.json")
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&allCookies)
	if err != nil {
		return
	}
}

func (userLogin *UserLogin) ResetCookies() {
	userLogin.client.SetCookieJar(tls_client.NewCookieJar())
}

func (userLogin *UserLogin) SaveCookies() *Error {
	u, _ := url.Parse("https://chatgpt.com")
	cookies := userLogin.client.GetCookieJar().Cookies(u)
	file, err := os.OpenFile("cookies.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	defer file.Close()
	filtered := []*http.Cookie{}
	expireTime := time.Now().AddDate(0, 0, 7)
	for _, cookie := range cookies {
		if cookie.Expires.After(expireTime) {
			filtered = append(filtered, cookie)
		}
	}
	allCookies[userLogin.Username] = filtered
	encoder := json.NewEncoder(file)
	err = encoder.Encode(allCookies)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	return nil
}

// func (userLogin *UserLogin) RenewWithCookies() *Error {
// 	cookies := allCookies[userLogin.Username]
// 	if len(cookies) == 0 {
// 		return NewError("readCookie", 0, "no cookies")
// 	}
// 	u, _ := url.Parse("https://chat.openai.com")
// 	userLogin.client.GetCookieJar().SetCookies(u, cookies)
// 	accessToken, statusCode, err := userLogin.GetAccessTokenInternal("")
// 	if err != nil {
// 		return NewError("renewToken", statusCode, err.Error())
// 	}
// 	userLogin.Result.AccessToken = accessToken
// 	return nil
// }

func (userLogin *UserLogin) GetAuthResult() Result {
	return userLogin.Result
}

// 注册后首次登录第七步
func (userLogin *UserLogin) GetFirstLoginCbCode(deviceId, state, codeChallenge string) (string, error) {
	// 构造形如 https://auth0.openai.com/authorize?issuer=xxx 的请求并获取返回的Code
	// 返回形如 https://platform.openai.com/auth/callback?code=xxxx&state=yyyy
	baseUrl := "https://auth0.openai.com/authorize"
	parsedUrl, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}
	qsParams := url.Values{
		"issuer":                []string{"auth0.openai.com"},
		"client_id":             []string{"DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD"},
		"audience":              []string{"https://api.openai.com/v1"},
		"redirect_uri":          []string{"https://platform.openai.com/auth/callback"},
		"device_id":             []string{deviceId},
		"scope":                 []string{"openid profile email offline_access"},
		"response_type":         []string{"code"},
		"response_mode":         []string{"query"},
		"state":                 []string{state},
		"code_challenge":        []string{codeChallenge},
		"code_challenge_method": []string{"S256"},
		"auth0Client":           []string{"eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"},
		// "nonce":        []string{},
	}
	// 将查询参数附加到URL上
	parsedUrl.RawQuery = qsParams.Encode()

	req, err := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)

	req.Header.Set("User-Agent", userLogin.userAgent)
	// req.Header.Set("sec-ch-ua-arch", "x86")
	// req.Header.Set("sec-ch-ua-bitness", "64")

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("跳转后获取 authorize?issuer 的返回状态码不是302,请检查。 状态码为 %d ", resp.StatusCode)
	}

	location := resp.Header.Get("location")
	// 从location中解析出code
	parsedRespUrl, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	code := parsedRespUrl.Query().Get("code")

	if code == "" {
		return "", fmt.Errorf("authorize?issuer 的返回url中没有code参数, 返回url为 %s ", location)
	}

	return code, nil
}

// 注册后首次登录第八步
func (userLogin *UserLogin) GetFirstLoginToken(code, codeVerifier string) (string, error) {
	// 成功状态码为200, 返回的结构体包含access_token、refresh_token、id_token、scope(值为openid profile email offline_access)、expires_in、token_type(值为Bearer)
	postTokenReqUrl := "https://auth0.openai.com/oauth/token"
	postData := map[string]string{
		"client_id":     "DRivsnm2Mu42T3KOpqdtwB3NYviHYzwD",
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": codeVerifier,
		"redirect_uri":  "https://platform.openai.com/auth/callback",
	}
	bodyBytes, err := json.Marshal(postData)
	if err != nil {
		return "", err
	}
	bodyStr := string(bodyBytes)
	req, err := http.NewRequest(http.MethodPost, postTokenReqUrl, strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth0-Client", "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9")
	req.Header.Set("User-Agent", userLogin.userAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	// 只有返回200才算成功
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("postTokenReqUrl 出错，返回的状态码不是200。 resp.StatusCode is %d", resp.StatusCode)
	}

	var respStrcut struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&respStrcut)
	if err != nil {
		return "", err
	}

	if respStrcut.AccessToken == "" {
		return "", fmt.Errorf("postTokenReqUrl 返回的数据中不包含 access_token 字段")
	}

	return respStrcut.AccessToken, nil
}

// 注册后首次登录第九步
func (userLogin *UserLogin) GetFirstLoginArkosePayload(accessToken string) (string, error) {
	// POST 数据到 dashboard/onboarding/login
	// 状态码为200表示成功，返回 ip_country(ip所在国家代码)、arkose_enabled、arkose_data_payload(下个接口主要使用这个字段)
	getArkoseBlobValUrl := "https://api.openai.com/dashboard/onboarding/login"
	bodyStr := string("{}")
	req, err := http.NewRequest(http.MethodPost, getArkoseBlobValUrl, strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", userLogin.userAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	// 只有返回200才算成功
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getArkoseBlobValUrl 出错，返回的状态码不是200。 resp.StatusCode is %d", resp.StatusCode)
	}

	var respStrcut struct {
		ArkoseDataPayload string `json:"arkose_data_payload"`
	}
	err = json.NewDecoder(resp.Body).Decode(&respStrcut)
	if err != nil {
		return "", err
	}

	if respStrcut.ArkoseDataPayload == "" {
		return "", fmt.Errorf("getArkoseBlobValUrl 返回的数据中不包含 arkose_data_payload 字段")
	}

	return respStrcut.ArkoseDataPayload, nil
}

// 注册后首次登录第十步, 获取初始化 Arkose
func (userLogin *UserLogin) GetFirstLoginInitArkoseToken(arkoseDataBlob string) (string, error) {
	arkResp, err := funcaptcha.GetOpenAiSignupToken(arkoseDataBlob, userLogin.client.GetProxy())
	if err != nil {
		return "", err
	}

	return arkResp.Token, nil
}

// 注册后首次登录第十一步，提交信息到create_account接口
func (userLogin *UserLogin) FirstLoginSubmitAccountInfo(email, accessToken, arkoseToken string) error {
	// POST 到 https://api.openai.com/dashboard/onboarding/create_account
	// 返回 200 表示成功

	log.Printf("OpenAI-Sentinel-Arkose-Tokent %s", arkoseToken)

	createAccountUrl := "https://api.openai.com/dashboard/onboarding/create_account"
	username := getUsernameFromEmail(email)
	usernamePref := "aa"
	if len(username) > 2 {
		usernamePref = username[:2]
	}
	birthDate := getValidRegBirthDate()
	postData := map[string]string{
		"app":       "chat",
		"name":      username,
		"picture":   fmt.Sprintf("https://s.gravatar.com/avatar/a382407675377f722d9097bed06eabe7?s=480&r=pg&d=https://cdn.auth0.com/avatars/%s.png", usernamePref),
		"birthdate": birthDate,
	}
	bodyBytes, err := json.Marshal(postData)
	if err != nil {
		return err
	}
	bodyStr := string(bodyBytes)
	req, err := http.NewRequest(http.MethodPost, createAccountUrl, strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("OpenAI-Sentinel-Arkose-Tokent", arkoseToken)
	req.Header.Set("User-Agent", userLogin.userAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	// 只有返回200才算成功
	if resp.StatusCode != http.StatusOK {
		respBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			respStr := string(respBytes)
			log.Printf("账号 %s 在调用 create_account 接口失败，状态码为 %d, 返回为为 %s", email, resp.StatusCode, respStr)
		}
		return fmt.Errorf("createAccountUrl 出错，返回的状态码不是200。 resp.StatusCode is %d", resp.StatusCode)
	}

	return nil
}

// 构造返回url的CloudFlare 403错误
func NewCloudFlare403ErrorMessage(url string) string {

	return fmt.Sprintf("url %s may have encountered Cloudflare's anti-bot protection, please send the request with cookies", url)
}

func generateCodeVerifier() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	verifier := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes)
	return verifier, nil
}

func generateCodeChallenge(codeVerifier string) (string, error) {
	// 对codeVerifier进行SHA-256哈希
	h := sha256.New()
	_, err := h.Write([]byte(codeVerifier))
	if err != nil {
		return "", err
	}
	hashed := h.Sum(nil)

	// 对哈希结果进行Base64 URL安全编码，并移除尾随的等号
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)
	return codeChallenge, nil
}

// 获取Email的@之前的部分
func getUsernameFromEmail(email string) string {
	if email == "" {
		return "abcd"
	}

	emailArr := strings.Split(email, "@")

	return emailArr[0]
}

func getValidRegBirthDate() string {
	// 生成一个18-60岁的出生日期，形如 1999-01-01

	now := time.Now()
	// 生成一个介于18年前和60年前之间的随机数
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	yearsAgo := rnd.Intn(43) + 18
	date := now.AddDate(-yearsAgo, 0, 0)

	// 将日期格式化成 "1999-01-01" 这样的形式
	formattedDate := date.Format("2006-01-02")

	return formattedDate
}
