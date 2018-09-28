package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type Handshake struct {
	Source string
	Packet []byte
}

type Banner struct {
	Source string `json:"source"`
	Banner []byte `json:"banner"`
}

type Service struct {
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"`
	SSL          bool     `json:"ssl"`
	Certificates [][]byte `json:"certificates"`
	Banner       Banner   `json:"banner"`
}

var handshakes = []Handshake{
	{"null", []byte("")},
	{"generic_lines", []byte("\r\n\r\n")},
	{"http", []byte("GET / HTTP/1.0\r\n\r\n")},
}

var httpSendToHTTPSBanner = []byte("\x15\x03\x01\x00\x02\x02\n")

var httpSendToHTTPSKeywords = [][]byte{
	[]byte("use the HTTPS scheme to access"),
	[]byte("plain HTTP request was sent to HTTPS port"),
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	host := flag.String("ip", "127.0.0.1", "ip")
	port := flag.Int("port", 80, "port")
	protocol := flag.String("protocol", "tcp", "protocol")
	bannerSize := flag.Int("banner", 1024, "banner size")
	connectTimeout := flag.Duration("connect", time.Second, "connect timeout")
	sslTimeout := flag.Duration("ssl", time.Second, "ssl handshake timeout")
	readWriteTimeout := flag.Duration("readWrite", time.Second, "read write timeout")
	flag.Parse()

	service, err := grab(*host, *port, *protocol, *bannerSize, *connectTimeout, *sslTimeout, *readWriteTimeout)
	if err != nil {
		log.Fatalf("error while grabbing: %v\n", err)
	}
	if data, err := json.Marshal(service); err != nil {
		log.Fatalf("error while marshalling to json: %v\n", err)
	} else {
		fmt.Println(string(data))
	}
}

func grab(host string, port int, protocol string, bannerSize int, connectTimeout, sslTimeout, readWriteTimeout time.Duration) (*Service, error) {
	protocol = strings.ToLower(protocol)
	if protocol != "tcp" && protocol != "udp" {
		return nil, errors.New("no such protocol")
	}

	// TODO support udp protocol
	if protocol == "udp" {
		return &Service{IP: host, Port: port, Protocol: "udp", Banner: Banner{Banner: []byte{}}}, nil
	}

	service := &Service{IP: host, Port: port, Protocol: protocol}
	defer func() {
		if service.Certificates == nil {
			service.Certificates = [][]byte{}
		}
		if service.Banner.Banner == nil {
			service.Banner.Banner = []byte{}
		}
	}()

	// raw
	for _, handshake := range handshakes {
		banner, _ := sendRecvTCP(host, port, handshake.Packet, bannerSize, connectTimeout, readWriteTimeout)
		if banner != nil {
			// http request sent to https
			var certificates [][]byte
			var httpsBanner []byte
			if handshake.Source == "http" && isHTTPSendToHTTPS(banner) {
				certificates, httpsBanner, _ = sendRecvTCPSSL(host, port, handshake.Packet, bannerSize, connectTimeout, sslTimeout, readWriteTimeout)
			}

			if certificates != nil {
				service.SSL = true
				service.Certificates = certificates
			}
			service.Banner.Source = handshake.Source
			if httpsBanner != nil {
				service.Banner.Banner = httpsBanner
			} else {
				service.Banner.Banner = banner
			}

			return service, nil
		}
	}

	// ssl
	var banner []byte
	for _, handshake := range handshakes {
		service.Certificates, banner, _ = sendRecvTCPSSL(host, port, handshake.Packet, bannerSize, connectTimeout, sslTimeout, readWriteTimeout)
		if !service.SSL && service.Certificates != nil {
			service.SSL = true
		}
		if banner != nil {
			service.Banner.Source = handshake.Source
			service.Banner.Banner = banner
			return service, nil
		}
	}

	return service, nil
}

func sendRecvTCP(host string, port int, handshake []byte, bannerSize int, connectTimeout, readWriteTimeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), connectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return sendRecv(conn, readWriteTimeout, handshake, bannerSize)
}

func sendRecvTCPSSL(host string, port int, handshake []byte, bannerSize int, connectTimeout, sslTimeout, readWriteTimeout time.Duration) ([][]byte, []byte, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), connectTimeout)
	if err != nil {
		return nil, nil, err
	}
	client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer client.Close()

	if err = client.SetReadDeadline(time.Now().Add(sslTimeout)); err != nil {
		return nil, nil, err
	}
	if err = client.SetWriteDeadline(time.Now().Add(sslTimeout)); err != nil {
		return nil, nil, err
	}
	if err = client.Handshake(); err != nil {
		return nil, nil, err
	}

	var certificates [][]byte
	for _, cert := range client.ConnectionState().PeerCertificates {
		certificates = append(certificates, cert.Raw)
	}

	if banner, err := sendRecv(client, readWriteTimeout, handshake, bannerSize); err != nil {
		return certificates, nil, err
	} else {
		return certificates, banner, nil
	}
}

func sendRecv(conn net.Conn, timeout time.Duration, handshake []byte, bannerSize int) ([]byte, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(handshake); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	banner := make([]byte, bannerSize)
	if n, err := conn.Read(banner); err != nil || n == 0 {
		return nil, err
	} else if n < bannerSize {
		banner = banner[:n]
	}

	return banner, nil
}

func isHTTPSendToHTTPS(banner []byte) bool {
	if bytes.Equal(banner, httpSendToHTTPSBanner) {
		return true
	}

	if len(banner) > 13 && bytes.Equal(banner[9:12], []byte("400")) {
		for _, keyword := range httpSendToHTTPSKeywords {
			if bytes.Contains(banner, keyword) {
				return true
			}
		}
	}

	return false
}
