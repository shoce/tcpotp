/*
history:
2016-0203 v1
2021-0223 otp

GoFmt GoBuildNull GoBuild GoRelease
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	TAB = "\t"
	NL  = "\n"

	TimestampLayout = "2006.0102.1504"

	MaxPasswordLength  = 100
	AskPasswordTimeout = 2 * time.Second
)

func printUsage() {
	fmt.Print(`
Creates tcp pipe for an ip address after a valid otp sent to the socket.
Usage: tcppipe accept/dial addr1 accept/dial addr2
Example: tcppipe dial 127.1:9022 dial 127.1:22
Example: tcppipe accept 127.1:8022 accept 127.1:9022
Env vars:
	Timeout [30s]- timeout for tcp connections and between dials
	OtpPipeLifetime [2h] - lifetime of a pipe after a successful otp validation
	OtpListPath [otp.list.text] - path to otp list file
	OtpLogPath [otp.log.text] - path to otp usage log file
`)
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
			log.Printf("otp log record invalid: `%s`", otprecord)
			continue
		}
		password, addr, expires := rr[0], rr[1], rr[2]
		if exptime, err := time.Parse(TimestampLayout, expires); err != nil {
			log.Printf("otp log record invalid expiration time: `%s`", expires)
			continue
		} else {
			OtpLog = append(OtpLog, OtpRecord{password, addr, exptime})
		}
	}

	return OtpLog, nil
}

func isValidInConn(conn *net.Conn) bool {
	remote := remoteAddr(conn)
	log.Printf("remote:%s", remote)

	if OtpLog, err := getOtpLog(); err != nil {
		log.Printf("get otp log error: %v", err)
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
	log.Printf("remote:%s password:%s", remoteAddr(conn), password)

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
						log.Printf("ask password error: %v", err)
					} else {
						log.Printf("remote:%s successfully authenticated for %v", remoteAddr(&conn), OtpPipeLifetime)
						if err := conn.SetWriteDeadline(time.Now().UTC().Add(10 * time.Second)); err == nil {
							conn.Write([]byte(fmt.Sprintf("remote:%s successfully authenticated for %v\n", remoteAddr(&conn), OtpPipeLifetime)))
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
			time.Sleep(Timeout)
		}
	}(allow, addr, connch)
	return
}

func allowConn(cmd string, addr string) (allow chan bool, connch chan *net.Conn, err error) {
	switch cmd {
	case "accept":
		allow, connch, err = allowAccept(addr)
	case "dial":
		allow, connch, err = allowDial(addr)
	default:
		err = fmt.Errorf("Cannon parse command `%s`: should be accept/dial", cmd)
	}
	return
}

var (
	Timeout time.Duration

	OtpListPath     string
	OtpLogPath      string
	OtpPipeLifetime time.Duration
)

func main() {
	var err error

	if len(os.Args) != 5 {
		fmt.Printf("Args: %+v", os.Args)
		printUsage()
		os.Exit(1)
	}

	TimeoutString := os.Getenv("Timeout")
	if TimeoutString == "" {
		TimeoutString = "30s"
	}
	Timeout, err = time.ParseDuration(TimeoutString)
	if err != nil {
		log.Fatal(err)
	}

	OtpPipeLifetimeString := os.Getenv("OtpPipeLifetimeString")
	if OtpPipeLifetimeString == "" {
		OtpPipeLifetimeString = "2h"
	}
	OtpPipeLifetime, err = time.ParseDuration(OtpPipeLifetimeString)
	if err != nil {
		log.Fatal(err)
	}

	OtpListPath = os.Getenv("OtpListPath")
	if OtpListPath == "" {
		OtpListPath = "otp.list.text"
	}
	OtpLogPath = os.Getenv("OtpLogPath")
	if OtpLogPath == "" {
		OtpLogPath = "otp.log.text"
	}

	cmd1, addr1 := os.Args[1], os.Args[2]
	al1, ch1, err := allowConn(cmd1, addr1)
	if err != nil {
		log.Fatal(err)
	}

	cmd2, addr2 := os.Args[3], os.Args[4]
	al2, ch2, err := allowConn(cmd2, addr2)
	if err != nil {
		log.Fatal(err)
	}

	for {
		al1 <- true
		conn1 := <-ch1
		if conn1 == nil {
			continue
		}
		log.Printf("remote:%s local:%s ->", (*conn1).RemoteAddr(), (*conn1).LocalAddr())

		go func(conn1 *net.Conn) {
			defer (*conn1).Close()

			al2 <- true
			conn2 := <-ch2
			if conn2 == nil {
				return
			}
			log.Printf("remote:%s local:%s -> local:%s remote:%s", (*conn1).RemoteAddr(), (*conn1).LocalAddr(), (*conn2).LocalAddr(), (*conn2).RemoteAddr())

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
