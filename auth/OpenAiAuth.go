package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

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
	chatOpenAiCookies  string // chat.openai.com 需要的Cookies
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
		chatOpenAiCookies:  "",
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

	if resp.StatusCode == http.StatusFound {
		req, _ := http.NewRequest(http.MethodGet, Auth0Url+resp.Header.Get("Location"), nil)

		req.Header.Set("User-Agent", userLogin.userAgent)
		req.Header.Set("Cookie", userLogin.auth0OpenAiCookies)

		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		defer resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if strings.HasPrefix(location, "/u/mfa-otp-challenge") {
				return "", http.StatusBadRequest, errors.New("Login with two-factor authentication enabled is not supported currently.")
			}

			req, _ := http.NewRequest(http.MethodGet, location, nil)

			req.Header.Set("User-Agent", userLogin.userAgent)

			resp, err := userLogin.client.Do(req)
			if err != nil {
				return "", http.StatusInternalServerError, err
			}

			defer resp.Body.Close()
			if resp.StatusCode == http.StatusFound {
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

		if resp.StatusCode == http.StatusForbidden {
			return "", resp.StatusCode, errors.New(NewCloudFlare403ErrorMessage(Auth0Url + resp.Header.Get("Location")))
		}

		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}

	if resp.StatusCode == http.StatusForbidden {
		return "", resp.StatusCode, errors.New(NewCloudFlare403ErrorMessage(LoginPasswordUrl + state))
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

// 构造返回url的CloudFlare 403错误
func NewCloudFlare403ErrorMessage(url string) string {

	return fmt.Sprintf("url %s may have encountered Cloudflare's anti-bot protection, please send the request with cookies", url)
}
