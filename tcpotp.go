/*
history:
2016-0203 tcppipe v1
2021-0223 otp

GoFmt GoBuildNull GoBuild GoRelease
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	TAB = "\t"
	NL  = "\n"

	TimestampLayout = "2006.0102.1504"

	MaxPasswordLength  = 100
	AskPasswordTimeout = 2 * time.Second

	Usage = `
Creates tcp pipe for an ip address after a valid otp sent to the socket.
Usage: tcpotp acceptAddr dialAddr
Example: tcpotp :9022 127.1:22
Example: tcpotp :5432 10.0.0.1:5432
Env vars:
	Timeout [30s]- timeout for tcp connections and between dials
	OtpPipeLifetime [2h] - lifetime of a pipe after a successful otp validation
	OtpListPath [otp.list.text] - path to otp list file
	OtpLogPath [otp.log.text] - path to otp usage log file
`
)

var (
	Timeout time.Duration

	OtpListPath     string
	OtpLogPath      string
	OtpPipeLifetime time.Duration

	TgToken               string
	TgChatIds             []int
	TgPrefix              string
	TgSuffix              string
	TgParseMode           = ""
	TgDisableNotification = true
)

func log(msg string, args ...interface{}) {
	const Beat = time.Duration(24) * time.Hour / 1000
	tzBiel := time.FixedZone("Biel", 60*60)
	t := time.Now().In(tzBiel)
	ty := t.Sub(time.Date(t.Year(), 1, 1, 0, 0, 0, 0, tzBiel))
	td := t.Sub(time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, tzBiel))
	ts := fmt.Sprintf(
		"%d/%d@%d",
		t.Year()%1000,
		int(ty/(time.Duration(24)*time.Hour))+1,
		int(td/Beat),
	)
	fmt.Fprintf(os.Stderr, ts+" "+msg+"\n", args...)
}

func tglog(msg string) {
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

	if TgPrefix != "" {
		msg = TgPrefix + msg
	}
	if TgSuffix != "" {
		msg = msg + TgSuffix
	}

	for _, chatid := range TgChatIds {
		smreq := TgSendMessageRequest{
			ChatId:              int64(chatid),
			Text:                msg,
			ParseMode:           TgParseMode,
			DisableNotification: TgDisableNotification,
		}
		smreqjs, err := json.Marshal(smreq)
		if err != nil {
			log("WARNING tglog %v", err)
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
			log("WARNING tglog apiurl:`%s` apidata:`%s` %v", tgapiurl, smreqjs, err)
		}

		var smresp TgSendMessageResponse
		err = json.NewDecoder(resp.Body).Decode(&smresp)
		if err != nil {
			log("WARNING tglog %v", err)
		}
		if !smresp.OK {
			log("WARNING tglog apiurl:`%s` apidata:`%s` api response not ok: %+v", tgapiurl, smreqjs, smresp)
		}
	}

}

func remoteAddr(conn *net.Conn) string {
	addr := (*conn).RemoteAddr().String()
	if li := strings.LastIndex(addr, ":"); li != -1 {
		addr = addr[:li]
	}
	return addr
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

func askPassInConn(conn *net.Conn) error {
	var err error
	passwordBytes := make([]byte, MaxPasswordLength)
	err = (*conn).SetReadDeadline(time.Now().Add(AskPasswordTimeout))
	if err != nil {
		return err
	}
	_, err = (*conn).Read(passwordBytes)
	if err != nil {
		return err
	}
	password := strings.TrimSpace(string(bytes.TrimRight(passwordBytes, "\x00")))
	log("remote:%s password:%s", remoteAddr(conn), password)

	if OtpLog, err := getOtpLog(); err != nil {
		return fmt.Errorf("get otp log error: %v", err)
	} else {
		for _, r := range OtpLog {
			if password == r.Password {
				return fmt.Errorf("password:%s was used before by remote:%s", password, r.Addr)
			}
		}
	}

	var OtpList []string
	if OtpListBytes, err := ioutil.ReadFile(OtpListPath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		OtpList = strings.Split(string(OtpListBytes), NL)
		var OtpList2 []string
		for _, s := range OtpList {
			if s2 := strings.TrimSpace(s); s2 != "" && !strings.Contains(s2, TAB) {
				OtpList2 = append(OtpList2, s2)
			}
		}
		OtpList = OtpList2
	}
	if len(OtpList) == 0 {
		return fmt.Errorf("empty otp list")
	}

	for _, p := range OtpList {
		if password == p {
			if OtpLogFile, err := os.OpenFile(OtpLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err != nil {
				return err
			} else {
				otprecord := fmt.Sprintf("%s"+TAB+"%s"+TAB+"%s"+NL, password, remoteAddr(conn), time.Now().UTC().Add(OtpPipeLifetime).Format(TimestampLayout))
				if _, err := OtpLogFile.Write([]byte(otprecord)); err != nil {
					OtpLogFile.Close()
					return err
				}
				if err := OtpLogFile.Sync(); err != nil {
					OtpLogFile.Close()
					return err
				}
				if err := OtpLogFile.Close(); err != nil {
					return err
				}
			}

			return nil
		}
	}

	return fmt.Errorf("invalid password: `%s`", password)
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
			l.(*net.TCPListener).SetDeadline(time.Now().Add(Timeout))
			conn, err := l.Accept()
			if err == nil {
				if isValidInConn(&conn) {
					connch <- &conn
					continue
				} else {
					if err := askPassInConn(&conn); err != nil {
						log("ask password: %v", err)
					} else {
						authmsg := fmt.Sprintf("address %s successfully authenticated for duration %d minutes", remoteAddr(&conn), int(OtpPipeLifetime.Minutes()))
						log(authmsg)
						tglog(authmsg)
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

func init() {
	var err error

	if len(os.Args) != 3 {
		fmt.Printf("Args: %+v\n", os.Args)
		fmt.Print(Usage)
		os.Exit(1)
	}

	TimeoutString := os.Getenv("Timeout")
	if TimeoutString == "" {
		TimeoutString = "30s"
	}
	Timeout, err = time.ParseDuration(TimeoutString)
	if err != nil {
		log("ERROR Parse Timeout duration: %v", err)
		os.Exit(1)
	}

	OtpPipeLifetimeString := os.Getenv("OtpPipeLifetime")
	if OtpPipeLifetimeString == "" {
		OtpPipeLifetimeString = "2h"
	}
	OtpPipeLifetime, err = time.ParseDuration(OtpPipeLifetimeString)
	if err != nil {
		log("ERROR Parse OtpPipeLifetime duration: %v", err)
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
		log("WARNING Empty TgToken env var")
	}

	for _, i := range strings.Split(os.Getenv("TgChatId"), ",") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			log("WARNING Invalid chat id `%s`", i)
		}
		TgChatIds = append(TgChatIds, chatid)
	}
	if len(TgChatIds) == 0 {
		log("WARNING Empty or invalid TgChatId env var")
	}

	TgPrefix = os.Getenv("TgPrefix")
	TgSuffix = os.Getenv("TgSuffix")
}

func main() {
	var err error

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

type timeoutConn struct {
	Conn net.Conn
}

func (c timeoutConn) Read(buf []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(Timeout))
	return c.Conn.Read(buf)
}

func (c timeoutConn) Write(buf []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(Timeout))
	return c.Conn.Write(buf)
}
