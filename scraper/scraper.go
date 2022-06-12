package scraper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

var (
	loginCheckTokenRegexp = regexp.MustCompile(`createHiddenInput\("Frm_Loginchecktoken", "(\d+)"\)`)
	loginTokenRegexp      = regexp.MustCompile(`createHiddenInput\("Frm_Logintoken", "(\d+)"\)`)

	ErrNeedLogin = errors.New("f660: need login")
)

type LoginTokens struct {
	Token      string
	CheckToken string
}

type Scraper struct {
	BaseURL   string
	CookieJar http.CookieJar

	User string
	Pass string
}

func (s *Scraper) GetLoginTokens(ctx context.Context) (LoginTokens, error) {
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL, nil)
	if err != nil {
		return LoginTokens{}, err
	}

	r, err := c.Do(req)
	if err != nil {
		return LoginTokens{}, err
	}

	respBuf := &bytes.Buffer{}
	_, err = respBuf.ReadFrom(r.Body)
	if err != nil {
		return LoginTokens{}, err
	}
	defer r.Body.Close()

	tokens := LoginTokens{}
	submatches := loginCheckTokenRegexp.FindStringSubmatch(respBuf.String())
	if len(submatches) == 0 {
		return LoginTokens{}, nil
	}

	tokens.CheckToken = submatches[1]

	submatches = loginTokenRegexp.FindStringSubmatch(respBuf.String())
	if len(submatches) == 0 {
		return tokens, nil
	}

	tokens.Token = submatches[1]

	return tokens, nil
}

func (s *Scraper) Login(ctx context.Context, loginTokens LoginTokens) error {
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	randomNum := strconv.Itoa(rand.Intn(89999999) + 10000000)

	buf := bytes.Buffer{}
	buf.WriteString(s.Pass)
	buf.WriteString(randomNum)

	sha256Sum := sha256.Sum256(buf.Bytes())

	body := url.Values{}
	body.Set("action", "login")
	body.Set("Username", s.User)
	body.Set("Password", hex.EncodeToString(sha256Sum[:]))
	body.Set("Frm_Logintoken", loginTokens.Token)
	body.Set("UserRandomNum", randomNum)
	body.Set("Frm_Loginchecktoken", loginTokens.CheckToken)

	bodyBuf := bytes.NewBufferString(body.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL, bodyBuf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	// TODO(gifff): use log!
	// fmt.Println("Login: Status Code: ", r.StatusCode)

	if r.StatusCode != http.StatusFound {
		return ErrNeedLogin
	}

	return nil
}

func (s *Scraper) Logout(ctx context.Context) error {
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	body := url.Values{}
	body.Set("logout", "1")
	body.Set("logout_from", "login_timeout")

	bodyBuf := bytes.NewBufferString(body.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL, bodyBuf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusFound {
		return ErrNeedLogin
	}

	return nil
}

func (s *Scraper) EnsureLogin(ctx context.Context) error {
	// using ethernet stats page as reference
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.BaseURL+"getpage.gch?pid=1002&nextpage=pon_status_lan_info_t.gch",
		nil,
	)
	if err != nil {
		return fmt.Errorf("EnsureLogin: failed to construct http request: %w", err)
	}

	r, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("EnsureLogin: failed to execute http request: %w", err)
	}
	defer r.Body.Close()

	// use table id TestContent as reference if the session is still valid or expired
	lanTableSelector, err := cascadia.Compile("table#TestContent")
	if err != nil {
		return fmt.Errorf("EnsureLogin: failed to compile cascadia selector: %w", err)
	}

	doc, err := html.Parse(r.Body)
	if err != nil {
		return fmt.Errorf("EnsureLogin: failed to parse html: %w", err)
	}

	nodes := cascadia.QueryAll(doc, lanTableSelector)
	if len(nodes) == 0 {
		return s.relogin(ctx)
	}

	return nil
}

func (s *Scraper) relogin(ctx context.Context) error {
	err := s.Logout(ctx)
	if err != nil {
		return err
	}

	t, err := s.GetLoginTokens(ctx)
	if err != nil {
		return err
	}

	return s.Login(ctx, t)
}

func (s *Scraper) GetLANStats(ctx context.Context) ([]LANStat, error) {
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.BaseURL+"getpage.gch?pid=1002&nextpage=pon_status_lan_info_t.gch",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("GetLANStats: failed to construct http request: %w", err)
	}

	r, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetLANStats: failed to execute http request: %w", err)
	}
	defer r.Body.Close()

	return parseLANStats(r.Body)
}

func (s *Scraper) GetWANStats(ctx context.Context) (*WANStats, error) {
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.BaseURL+"getpage.gch?pid=1002&nextpage=IPv46_status_wan2_if_t.gch",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("GetWANStats: failed to construct http request: %w", err)
	}

	r, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetWANStats: failed to execute http request: %w", err)
	}
	defer r.Body.Close()

	return parseWANStats(r.Body)
}

func (s *Scraper) GetWLANStats(ctx context.Context) ([]WLANStat, error) {
	c := &http.Client{
		Jar:     s.CookieJar,
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.BaseURL+"getpage.gch?pid=1002&nextpage=status_wlanm_info1_t.gch",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("GetWLANStats: failed to construct http request: %w", err)
	}

	r, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetWLANStats: failed to execute http request: %w", err)
	}
	defer r.Body.Close()

	buf := &bytes.Buffer{}
	_, err = buf.ReadFrom(r.Body)
	if err != nil {
		return nil, fmt.Errorf("GetWLANStats: failed to read response body: %w", err)
	}

	wlanData := parseWLANData(buf.String())

	numberOfSSIDs := 4
	if n, err := strconv.Atoi(wlanData["IF_INSTNUM"]); err == nil {
		numberOfSSIDs = n
	}

	wlanStats := make([]WLANStat, 0, numberOfSSIDs)

	for i := 0; i < numberOfSSIDs; i++ {
		wlanStat := WLANStat{
			Enabled:                   wlanData[fmt.Sprintf("Enable%d", i)] == "1",
			Name:                      wlanData[fmt.Sprintf("ESSID%d", i)],
			MACAddress:                strings.ReplaceAll(wlanData[fmt.Sprintf("Bssid%d", i)], "\\x3a", ":"),
			PacketsReceived:           parseInt64(wlanData[fmt.Sprintf("TotalPacketsReceived%d", i)]),
			PacketsSent:               parseInt64(wlanData[fmt.Sprintf("TotalPacketsSent%d", i)]),
			BytesReceived:             parseInt64(wlanData[fmt.Sprintf("TotalBytesReceived%d", i)]),
			BytesSent:                 parseInt64(wlanData[fmt.Sprintf("TotalBytesSent%d", i)]),
			ErrorPacketsReceived:      parseInt64(wlanData[fmt.Sprintf("ErrorReceived%d", i)]),
			ErrorPacketsSent:          parseInt64(wlanData[fmt.Sprintf("ErrorSent%d", i)]),
			DiscardedReceivingPackets: parseInt64(wlanData[fmt.Sprintf("DiscardPacketsReceived%d", i)]),
			DiscardedSendingPackets:   parseInt64(wlanData[fmt.Sprintf("DiscardPacketsSent%d", i)]),
		}

		wlanStat.AuthenticationType, wlanStat.EncryptionType = parseWLANModes(wlanData, i)

		wlanStats = append(wlanStats, wlanStat)
	}

	return wlanStats, nil
}
