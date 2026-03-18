// GoGet GoFmt GoBuildNull

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
	SP  = " "
	TAB = "\t"
	NL  = "\n"

	OtpListPathDef = "otp.list.text"
	OtpLogPathDef  = "otp.log.text"

	// TODO "2006:0102:1504"
	TimestampLayout = "2006.0102.1504"

	MaxPasswordLength  = 100
	AskPasswordTimeout = 2 * time.Second

	OtpPipeLifetimeDef = 1 * time.Hour
	TcpTimeoutDef      = 60 * time.Second

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
	OtpListPath [` + OtpListPathDef + `] - path to otp list file
	OtpLogPath [` + OtpLogPathDef + `] - path to otp usage log file
	TgToken - telegram api token
	TgLogChatIds - list of chat ids to log auth events (example: "123,-321")
	TgBossChatIds - list of chat ids to send new passwords to (example: "456")
	TgLogPrefix - prefix for every auth event log
	TgLogSuffix - suffix for every auth event log
`
)

var (
	DEBUG bool

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
		perr("args %+v"+NL, os.Args)
		perr("%s", Usage)
		os.Exit(1)
	}

	if os.Getenv("DEBUG") != "" {
		DEBUG = true
	}

	if v := os.Getenv("TcpTimeout"); v != "" {
		TcpTimeout, err = time.ParseDuration(v)
		if err != nil {
			perr("ERROR parse TcpTimeout duration %v", err)
			os.Exit(1)
		}
	} else {
		TcpTimeout = TcpTimeoutDef
	}

	if v := os.Getenv("OtpPipeLifetime"); v != "" {
		OtpPipeLifetime, err = time.ParseDuration(v)
		if err != nil {
			perr("ERROR parse OtpPipeLifetime duration %v", err)
			os.Exit(1)
		}
	} else {
		OtpPipeLifetime = OtpPipeLifetimeDef
	}

	OtpListPath = os.Getenv("OtpListPath")
	if OtpListPath == "" {
		OtpListPath = OtpListPathDef
	}
	OtpLogPath = os.Getenv("OtpLogPath")
	if OtpLogPath == "" {
		OtpLogPath = OtpLogPathDef
	}

	TgToken = os.Getenv("TgToken")
	if TgToken == "" {
		perr("WARNING empty TgToken env var")
	}

	for _, i := range strings.Split(os.Getenv("TgLogChatId"), ",") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			perr("WARNING invalid TgLogChatId chat id [%s]", i)
		}
		TgLogChatIds = append(TgLogChatIds, chatid)
	}
	if len(TgLogChatIds) == 0 {
		perr("WARNING empty or invalid TgLogChatId env var")
	}

	for _, i := range strings.Split(os.Getenv("TgBossChatId"), ",") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			perr("WARNING invalid TgBossChatId chat id [%s]", i)
		}
		TgBossChatIds = append(TgBossChatIds, chatid)
	}
	if len(TgBossChatIds) == 0 {
		perr("WARNING empty or invalid TgBossChatId env var")
	}

	TgLogPrefix = os.Getenv("TgLogPrefix")
	TgLogSuffix = os.Getenv("TgLogSuffix")
}

func main() {
	var err error

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		perr("signal [%s] received - exiting", s)
		os.Exit(0)
	}()

	if _, err := getOtpList(); err != nil {
		perr("ERROR get otp list %v", err)
		os.Exit(1)
	}

	otplog, err := getOtpLog()
	if err != nil {
		perr("ERROR get otp log %v", err)
		os.Exit(1)
	}
	for _, r := range otplog {
		if tillexpire := r.Expire.Sub(time.Now()); tillexpire > 0 {
			raddr := r.Addr
			time.AfterFunc(tillexpire, func() {
				finmsg := fmt.Sprintf(
					"ip address %s session finished"+NL,
					raddr,
				)
				err := tglog(finmsg, TgLogChatIds)
				if err != nil {
					perr("ERROR tglog %v", err)
				}
			})
		}
	}

	checkNumValidOtp()

	addr1, addr2 := os.Args[1], os.Args[2]

	al1, ch1, err := allowAccept(addr1)
	if err != nil {
		perr("ERROR allowAccept [%s] %v", addr1, err)
		os.Exit(1)
	}
	perr("DEBUG started goroutine to accept incoming connections")

	al2, ch2, err := allowDial(addr2)
	if err != nil {
		perr("ERROR allowDial [%s] %v", addr2, err)
		os.Exit(1)
	}
	perr("DEBUG started goroutine to dial outcoming connections")

	for {
		al1 <- true
		conn1 := <-ch1
		if conn1 == nil {
			continue
		}
		perr("remote [%s] local [%s] ->", (*conn1).RemoteAddr(), (*conn1).LocalAddr())

		go func(conn1 *net.Conn) {
			defer (*conn1).Close()

			al2 <- true
			conn2 := <-ch2
			if conn2 == nil {
				return
			}
			perr("remote [%s] local [%s] -> local [%s] remote [%s]", (*conn1).RemoteAddr(), (*conn1).LocalAddr(), (*conn2).LocalAddr(), (*conn2).RemoteAddr())

			defer (*conn2).Close()

			tconn1 := timeoutConn{*conn1}
			tconn2 := timeoutConn{*conn2}
			go io.Copy(*conn2, tconn1)
			io.Copy(*conn1, tconn2)
		}(conn1)
	}
}

func perr(msg string, args ...interface{}) {
	if strings.HasPrefix(msg, "DEBUG ") && !DEBUG {
		return
	}
	tnow := time.Now().Local()
	ts := fmt.Sprintf(
		"<%d:%02d%02d:%02d%02d>",
		tnow.Year()%1000, tnow.Month(), tnow.Day(),
		tnow.Hour(), tnow.Minute(),
	)
	msgtext := msg
	if len(args) > 0 {
		msgtext = fmt.Sprintf(msg, args...)
	}
	fmt.Fprint(os.Stderr, ts+SP+msgtext+NL)
}

func tglog(msgtext string, chatids []int) error {
	perr(msgtext)

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

	msgtext = TgLogPrefix + msgtext + TgLogSuffix

	for _, chatid := range chatids {
		smreq := TgSendMessageRequest{
			ChatId:              int64(chatid),
			Text:                msgtext,
			ParseMode:           TgParseMode,
			DisableNotification: TgDisableNotification,
		}
		smreqjs, err := json.Marshal(smreq)
		if err != nil {
			return fmt.Errorf("json marshal %v", err)
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
			return fmt.Errorf("http post url [%s] data [%s] %v", tgapiurl, smreqjs, err)
		}

		var smresp TgSendMessageResponse
		err = json.NewDecoder(resp.Body).Decode(&smresp)
		if err != nil {
			return fmt.Errorf("tg api reponse json decode %v", err)
		}
		if !smresp.OK {
			return fmt.Errorf("tg api response url [%s] data [%s] not ok %+v", tgapiurl, smreqjs, smresp)
		}
	}

	return nil
}

func getRemoteAddr(conn *net.Conn) string {
	addr := (*conn).RemoteAddr().String()
	if li := strings.LastIndex(addr, ":"); li != -1 {
		addr = addr[:li]
	}
	return addr
}

func newpass() string {
	var password strings.Builder
	for range NewPasswordLength {
		random := rand.Intn(len(NewPasswordCharSet))
		password.WriteString(string(NewPasswordCharSet[random]))
	}
	return password.String()
}

type OtpRecord struct {
	Password string
	Addr     string
	Expire   time.Time
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
			perr("otp log record invalid [%s]", otprecord)
			continue
		}
		password, addr, expires := rr[0], rr[1], rr[2]
		if exptime, err := time.Parse(TimestampLayout, expires); err != nil {
			perr("otp log record invalid expiration time [%s]", expires)
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
	numvalidotp, err := getNumValidOtp()
	if err != nil {
		perr("ERROR getNumValidOtp %v", err)
		os.Exit(1)
	}
	perr("count of valid one-time passwords available <%d>", numvalidotp)
	if numvalidotp == 0 {
		err := genNewOtp()
		if err != nil {
			perr("ERROR genNewOtp %v", err)
			os.Exit(1)
		}
	}
}

func genNewOtp() error {
	var pp []string
	for range NewPasswordListSize {
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

	tgmsg := fmt.Sprintf(
		"no valid one-time passwords left."+NL+
			"more one-time passwords:"+NL+
			"%s",
		pps,
	)
	if err = tglog(tgmsg, TgBossChatIds); err != nil {
		return fmt.Errorf("tglog %v", err)
	}
	perr("sent more one-time passwords to %+v", TgBossChatIds)

	return nil
}

func isValidInConn(conn *net.Conn) bool {
	remoteAddr := getRemoteAddr(conn)
	perr("remote [%s]", remoteAddr)

	OtpLog, err := getOtpLog()
	if err != nil {
		perr("ERROR get otp log %v", err)
		return false
	}

	for _, r := range OtpLog {
		if time.Now().After(r.Expire) {
			continue
		}
		if remoteAddr == r.Addr {
			return true
		}
	}

	return false
}

func askPassInConn(conn *net.Conn) (pw string, remoteAddrSeen bool, err error) {
	passwordBytes := make([]byte, MaxPasswordLength)
	err = (*conn).SetReadDeadline(time.Now().Add(AskPasswordTimeout))
	if err != nil {
		return "", false, err
	}
	_, err = (*conn).Read(passwordBytes)
	if err != nil {
		return "", false, err
	}
	password := strings.TrimSpace(string(bytes.TrimRight(passwordBytes, "\x00")))

	remoteAddr := getRemoteAddr(conn)
	perr("remote [%s] password [%s]", remoteAddr, strings.ReplaceAll(password, NL, "<NL>"))

	OtpLog, err := getOtpLog()
	if err != nil {
		return "", false, fmt.Errorf("get otp log %v", err)
	}

	for _, r := range OtpLog {
		if password == r.Password {
			return "", false, fmt.Errorf("password [%s] was used before by remote [%s]", password, r.Addr)
		}
	}

	remoteAddrSeen = false
	for _, r := range OtpLog {
		if r.Addr == remoteAddr {
			remoteAddrSeen = true
		}
	}

	OtpList, err := getOtpList()
	if err != nil {
		return "", remoteAddrSeen, err
	}
	if len(OtpList) == 0 {
		return "", remoteAddrSeen, fmt.Errorf("empty otp list")
	}

	for _, p := range OtpList {
		if p != password {
			continue
		}

		OtpLogFile, err := os.OpenFile(OtpLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return "", remoteAddrSeen, err
		}
		otprecord := fmt.Sprintf(
			"%s"+TAB+"%s"+TAB+"%s"+NL,
			password, remoteAddr, time.Now().UTC().Add(OtpPipeLifetime).Format(TimestampLayout),
		)
		if _, err := OtpLogFile.Write([]byte(otprecord)); err != nil {
			OtpLogFile.Close()
			return "", remoteAddrSeen, err
		}
		if err := OtpLogFile.Sync(); err != nil {
			OtpLogFile.Close()
			return "", remoteAddrSeen, err
		}
		if err := OtpLogFile.Close(); err != nil {
			return "", remoteAddrSeen, err
		}

		checkNumValidOtp()

		return password, remoteAddrSeen, nil
	}

	return "", remoteAddrSeen, fmt.Errorf("invalid password [%s]", strings.ReplaceAll(password, NL, "<NL>"))
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
			if err != nil {
				perr("ERROR accept incoming connection %v", err)
				connch <- nil
				continue
			}

			remoteAddr := getRemoteAddr(&conn)
			perr("DEBUG accepted incoming connection from remote [%s]", remoteAddr)

			if isValidInConn(&conn) {
				perr("DEBUG valid incoming connection from remote [%s]", remoteAddr)
				connch <- &conn
				continue
			}

			perr("DEBUG asking for password from remote [%s]", remoteAddr)
			pw, remoteAddrSeen, err := askPassInConn(&conn)
			if err != nil {
				perr("ERROR asking for password from remote [%s] %v", remoteAddr, err)
				connch <- nil
				continue
			}

			authmsg := fmt.Sprintf(
				"ip address %s successfully authenticated"+NL+
					"with one-time password %s"+NL+
					"for duration %d minutes"+NL,
				remoteAddr, pw, int(OtpPipeLifetime.Minutes()),
			)

			if !remoteAddrSeen {
				authmsg += "WARNING NEW IP ADDRESS" + NL
			}

			perr(authmsg)
			if err := tglog(authmsg, TgLogChatIds); err != nil {
				perr("ERROR tglog %v", err)
			}
			if err := conn.SetWriteDeadline(time.Now().UTC().Add(11 * time.Second)); err == nil {
				conn.Write([]byte(authmsg + NL))
			}

			conn.Close()

			time.AfterFunc(OtpPipeLifetime, func() {
				finmsg := fmt.Sprintf(
					"ip address %s session finished"+NL,
					remoteAddr,
				)
				err := tglog(finmsg, TgLogChatIds)
				if err != nil {
					perr("ERROR tglog %v", err)
				}
			})

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
