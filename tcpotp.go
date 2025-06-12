/*

GoGet GoFmt GoBuildNull

*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	TAB = "\t"
	NL  = "\n"

	TimestampLayout = "2006.0102.1504"

	MaxPasswordLength  = 100
	AskPasswordTimeout = 2 * time.Second

	TcpTimeoutStringDefault = "60s"

	NewPasswordCharSet  = "0123456789abcdedfghjkmnpqrstvwxyz"
	NewPasswordLength   = 40
	NewPasswordListSize = 12

	Usage = `
creates tcp pipe for an ip address after a valid otp sent to the socket.
usage: tcpotp acceptAddr dialAddr
example: tcpotp :9022 127.1:22
example: tcpotp :5432 10.0.0.1:5432
env vars (default value in square brackets):
	TcpTimeout [60s] - timeout for tcp connections and between dials
	OtpPipeLifetime [1h] - lifetime of a pipe after a successful otp validation
	OtpListPath [otp.list.text] - path to otp list file
	OtpLogPath [otp.log.text] - path to otp usage log file
	TgToken - telegram api token
	TgLogChatIds - list of chat ids to log auth events (example: "123,-321")
	TgBossChatIds - list of chat ids to send new passwords to (example: "456")
	TgLogPrefix - prefix for every auth event log
	TgLogSuffix - suffix for every auth event log
`
)

var (
	TcpTimeout time.Duration

	OtpListPath     string
	OtpLogPath      string
	OtpPipeLifetime time.Duration

	TgToken               string
	TgLogChatIds          []int
	TgBossChatIds         []int
	TgLogPrefix           string
	TgLogSuffix           string
	TgParseMode           = ""
	TgDisableNotification = true
)

func init() {
	var err error

	rand.Seed(time.Now().Unix())

	if len(os.Args) != 3 {
		fmt.Printf("args: %+v\n", os.Args)
		fmt.Print(Usage)
		os.Exit(1)
	}

	TcpTimeoutString := os.Getenv("TcpTimeout")
	if TcpTimeoutString == "" {
		TcpTimeoutString = TcpTimeoutStringDefault
	}
	TcpTimeout, err = time.ParseDuration(TcpTimeoutString)
	if err != nil {
		log("ERROR parse TcpTimeout duration: %v", err)
		os.Exit(1)
	}

	OtpPipeLifetimeString := os.Getenv("OtpPipeLifetime")
	if OtpPipeLifetimeString == "" {
		OtpPipeLifetimeString = "1h"
	}
	OtpPipeLifetime, err = time.ParseDuration(OtpPipeLifetimeString)
	if err != nil {
		log("ERROR parse OtpPipeLifetime duration: %v", err)
		os.Exit(1)
	}

	OtpListPath = os.Getenv("OtpListPath")
	if OtpListPath == "" {
		OtpListPath = "otp.list.text"
	}
	OtpLogPath = os.Getenv("OtpLogPath")
	if OtpLogPath == "" {
		OtpLogPath = "otp.log.text"
	}

	TgToken = os.Getenv("TgToken")
	if TgToken == "" {
		log("WARNING empty TgToken env var")
	}

	for _, i := range strings.Split(os.Getenv("TgLogChatId"), ",") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			log("WARNING Invalid chat id `%s`", i)
		}
		TgLogChatIds = append(TgLogChatIds, chatid)
	}
	if len(TgLogChatIds) == 0 {
		log("WARNING empty or invalid TgLogChatId env var")
	}

	for _, i := range strings.Split(os.Getenv("TgBossChatId"), ",") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			log("WARNING invalid chat id `%s`", i)
		}
		TgBossChatIds = append(TgBossChatIds, chatid)
	}
	if len(TgBossChatIds) == 0 {
		log("WARNING empty or invalid TgBossChatId env var")
	}

	TgLogPrefix = os.Getenv("TgLogPrefix")
	TgLogSuffix = os.Getenv("TgLogSuffix")
}

func main() {
	var err error

	if _, err := getOtpList(); err != nil {
		log("%v", err)
		os.Exit(1)
	}

	checkNumValidOtp()

	addr1, addr2 := os.Args[1], os.Args[2]
	al1, ch1, err := allowAccept(addr1)
	if err != nil {
		log("ERROR %v", err)
		os.Exit(1)
	}
	al2, ch2, err := allowDial(addr2)
	if err != nil {
		log("ERROR %v", err)
		os.Exit(1)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		log("signal `%s` received. exiting.", s)
		os.Exit(0)
	}()

	for {
		al1 <- true
		conn1 := <-ch1
		if conn1 == nil {
			continue
		}
		log("remote:%s local:%s ->", (*conn1).RemoteAddr(), (*conn1).LocalAddr())

		go func(conn1 *net.Conn) {
			defer (*conn1).Close()

			al2 <- true
			conn2 := <-ch2
			if conn2 == nil {
				return
			}
			log("remote:%s local:%s -> local:%s remote:%s", (*conn1).RemoteAddr(), (*conn1).LocalAddr(), (*conn2).LocalAddr(), (*conn2).RemoteAddr())

			defer (*conn2).Close()

			tconn1 := timeoutConn{*conn1}
			tconn2 := timeoutConn{*conn2}
			go io.Copy(*conn2, tconn1)
			io.Copy(*conn1, tconn2)
		}(conn1)
	}
}

func log(msg interface{}, args ...interface{}) {
	t := time.Now().Local()
	ts := fmt.Sprintf(
		"%03d."+"%02d%02d."+"%02d"+"%02d.",
		t.Year()%1000, t.Month(), t.Day(), t.Hour(), t.Minute(),
	)
	msgtext := fmt.Sprintf("%s %s", ts, msg) + NL
	fmt.Fprintf(os.Stderr, msgtext, args...)
}

func tglog(msg string, chatids []int) error {
	type TgSendMessageRequest struct {
		ChatId              int64  `json:"chat_id"`
		Text                string `json:"text"`
		ParseMode           string `json:"parse_mode,omitempty"`
		DisableNotification bool   `json:"disable_notification"`
	}

	type TgSendMessageResponse struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			MessageId int64 `json:"message_id"`
		} `json:"result"`
	}

	if TgLogPrefix != "" {
		msg = TgLogPrefix + msg
	}
	if TgLogSuffix != "" {
		msg = msg + TgLogSuffix
	}

	for _, chatid := range chatids {
		smreq := TgSendMessageRequest{
			ChatId:              int64(chatid),
			Text:                msg,
			ParseMode:           TgParseMode,
			DisableNotification: TgDisableNotification,
		}
		smreqjs, err := json.Marshal(smreq)
		if err != nil {
			return fmt.Errorf("tglog %v", err)
		}
		smreqjsBuffer := bytes.NewBuffer(smreqjs)

		var resp *http.Response
		tgapiurl := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TgToken)
		resp, err = http.Post(
			tgapiurl,
			"application/json",
			smreqjsBuffer,
		)
		if err != nil {
			return fmt.Errorf("tglog apiurl:`%s` apidata:`%s` %v", tgapiurl, smreqjs, err)
		}

		var smresp TgSendMessageResponse
		err = json.NewDecoder(resp.Body).Decode(&smresp)
		if err != nil {
			return fmt.Errorf("tglog %v", err)
		}
		if !smresp.OK {
			return fmt.Errorf("tglog apiurl:`%s` apidata:`%s` api response not ok: %+v", tgapiurl, smreqjs, smresp)
		}
	}

	return nil
}

func remoteAddr(conn *net.Conn) string {
	addr := (*conn).RemoteAddr().String()
	if li := strings.LastIndex(addr, ":"); li != -1 {
		addr = addr[:li]
	}
	return addr
}

func newpass() string {
	var password strings.Builder
	for i := 0; i < NewPasswordLength; i++ {
		random := rand.Intn(len(NewPasswordCharSet))
		password.WriteString(string(NewPasswordCharSet[random]))
	}
	return password.String()
}

type OtpRecord struct {
	Password string
	Addr     string
	Expires  time.Time
}

func getOtpLog() ([]OtpRecord, error) {
	var OtpLog []OtpRecord
	var OtpLogLines []string
	if OtpLogBytes, err := ioutil.ReadFile(OtpLogPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return nil, nil
	} else {
		OtpLogLines = strings.Split(string(OtpLogBytes), NL)
	}
	for _, otprecord := range OtpLogLines {
		if strings.TrimSpace(otprecord) == "" {
			continue
		}
		rr := strings.Split(otprecord, TAB)
		if len(rr) != 3 {
			log("otp log record invalid: `%s`", otprecord)
			continue
		}
		password, addr, expires := rr[0], rr[1], rr[2]
		if exptime, err := time.Parse(TimestampLayout, expires); err != nil {
			log("otp log record invalid expiration time: `%s`", expires)
			continue
		} else {
			OtpLog = append(OtpLog, OtpRecord{password, addr, exptime})
		}
	}

	return OtpLog, nil
}

func getOtpList() ([]string, error) {
	var OtpList []string
	if OtpListBytes, err := ioutil.ReadFile(OtpListPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		OtpListLines := strings.Split(string(OtpListBytes), NL)
		for _, s := range OtpListLines {
			if s = strings.TrimSpace(s); s != "" && !strings.HasPrefix(s, "#") {
				OtpList = append(OtpList, s)
			}
		}
	}

	return OtpList, nil
}

func getNumValidOtp() (int, error) {
	var err error
	var otplist, validotplist []string
	if otplist, err = getOtpList(); err != nil {
		return 0, err
	}
	if otplog, err := getOtpLog(); err != nil {
		return 0, err
	} else {
		for _, p := range otplist {
			valid := true
			for _, r := range otplog {
				if p == r.Password {
					valid = false
					break
				}
			}
			if valid {
				validotplist = append(validotplist, p)
			}
		}
	}
	return len(validotplist), nil
}

func checkNumValidOtp() {
	if numvalidotp, err := getNumValidOtp(); err != nil {
		log("%v", err)
		os.Exit(1)
	} else {
		log("count of valid one time passwords available: %d", numvalidotp)
		if numvalidotp == 0 {
			if err := genNewOtp(); err != nil {
				log("%v", err)
				os.Exit(1)
			}
		}
	}
}

func genNewOtp() error {
	var pp []string
	for i := 0; i < NewPasswordListSize; i++ {
		p := newpass()
		pp = append(pp, p)
	}
	pps := NL + strings.Join(pp, NL) + NL

	f, err := os.OpenFile(OtpListPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(pps)); err != nil {
		f.Sync()
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	err = tglog(fmt.Sprintf(
		"no valid one-time passwords left.\nmore one-time passwords:\n%s",
		pps,
	), TgBossChatIds)
	if err != nil {
		return err
	}
	log("sent more one-time passwords to %+v", TgBossChatIds)

	return nil
}

func isValidInConn(conn *net.Conn) bool {
	remote := remoteAddr(conn)
	log("remote:%s", remote)

	if OtpLog, err := getOtpLog(); err != nil {
		log("get otp log error: %v", err)
		return false
	} else {
		for _, r := range OtpLog {
			if time.Now().After(r.Expires) {
				continue
			}
			if remote == r.Addr {
				return true
			}
		}
	}

	return false
}

func askPassInConn(conn *net.Conn) (pw string, err error) {
	passwordBytes := make([]byte, MaxPasswordLength)
	err = (*conn).SetReadDeadline(time.Now().Add(AskPasswordTimeout))
	if err != nil {
		return "", err
	}
	_, err = (*conn).Read(passwordBytes)
	if err != nil {
		return "", err
	}
	password := strings.TrimSpace(string(bytes.TrimRight(passwordBytes, "\x00")))
	log("remote:%s password:%s", remoteAddr(conn), password)

	if OtpLog, err := getOtpLog(); err != nil {
		return "", fmt.Errorf("get otp log error: %v", err)
	} else {
		for _, r := range OtpLog {
			if password == r.Password {
				return "", fmt.Errorf("password:%s was used before by remote:%s", password, r.Addr)
			}
		}
	}

	var OtpList []string
	if OtpList, err = getOtpList(); err != nil {
		return "", err
	}
	if len(OtpList) == 0 {
		return "", fmt.Errorf("empty otp list")
	}

	for _, p := range OtpList {
		if password == p {
			if OtpLogFile, err := os.OpenFile(OtpLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
				return "", err
			} else {
				otprecord := fmt.Sprintf("%s"+TAB+"%s"+TAB+"%s"+NL, password, remoteAddr(conn), time.Now().UTC().Add(OtpPipeLifetime).Format(TimestampLayout))
				if _, err := OtpLogFile.Write([]byte(otprecord)); err != nil {
					OtpLogFile.Close()
					return "", err
				}
				if err := OtpLogFile.Sync(); err != nil {
					OtpLogFile.Close()
					return "", err
				}
				if err := OtpLogFile.Close(); err != nil {
					return "", err
				}
			}

			checkNumValidOtp()

			return password, nil
		}
	}

	return "", fmt.Errorf("invalid password: `%s`", password)
}

func allowAccept(addr string) (allow chan bool, connch chan *net.Conn, err error) {
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return
	}
	allow = make(chan bool)
	connch = make(chan *net.Conn)
	go func(allow chan bool, l net.Listener, connch chan *net.Conn) {
		for {
			<-allow
			l.(*net.TCPListener).SetDeadline(time.Now().Add(TcpTimeout))
			conn, err := l.Accept()
			if err == nil {
				if isValidInConn(&conn) {
					connch <- &conn
					continue
				} else {
					if pw, err := askPassInConn(&conn); err != nil {
						log("ask password: %v", err)
					} else {
						authmsg := fmt.Sprintf(
							"address %s successfully authenticated"+NL+
								"with one-time password %s"+NL+
								"for duration %d minutes",
							remoteAddr(&conn),
							pw,
							int(OtpPipeLifetime.Minutes()),
						)
						log(authmsg)
						tglog(authmsg, TgLogChatIds)
						if err := conn.SetWriteDeadline(time.Now().UTC().Add(10 * time.Second)); err == nil {
							conn.Write([]byte(authmsg + NL))
						}
					}
					conn.Close()
				}
			}
			connch <- nil
		}
	}(allow, l, connch)
	return
}

func allowDial(addr string) (allow chan bool, connch chan *net.Conn, err error) {
	allow = make(chan bool)
	connch = make(chan *net.Conn)
	go func(allow chan bool, addr string, connch chan *net.Conn) {
		for {
			<-allow
			conn, err := net.Dial("tcp4", addr)
			if err == nil {
				connch <- &conn
			} else {
				connch <- nil
			}
		}
	}(allow, addr, connch)
	return
}

type timeoutConn struct {
	Conn net.Conn
}

func (c timeoutConn) Read(buf []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(TcpTimeout))
	return c.Conn.Read(buf)
}

func (c timeoutConn) Write(buf []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(TcpTimeout))
	return c.Conn.Write(buf)
}
