package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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
	threads := flag.Int("threads", 1024, "threads")
	bannerSize := flag.Int("banner", 1024, "banner size")
	connectTimeout := flag.Duration("connect", time.Second, "connect timeout")
	sslTimeout := flag.Duration("ssl", time.Second, "ssl handshake timeout")
	readWriteTimeout := flag.Duration("readWrite", time.Second, "read write timeout")
	flag.Parse()

	input := make(chan *Service, 1024)
	output := make(chan *Service, 1024)
	done := make(chan struct{}, *threads)

	// input
	go func() {
		scanner := bufio.NewScanner(os.Stdin)

		for scanner.Scan() {
			data := scanner.Bytes()
			var service Service
			if err := json.Unmarshal(data, &service); err != nil {
				log.Printf("error while unmarshalling data to Service: %v\n", err)
				continue
			}
			input <- &service
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("error while reading from stdin: %v\n", err)
		}

		close(input)
	}()

	// grab
	for i := 0; i < *threads; i++ {
		go func() {
			for service := range input {
				service, _ = grab(service, *bannerSize, *connectTimeout, *sslTimeout, *readWriteTimeout)
				output <- service
			}
			done <- struct{}{}
		}()
	}

	// output
	go func() {
		for i := 0; i < *threads; i++ {
			<-done
		}
		close(output)
	}()

	for service := range output {
		data, err := json.Marshal(service)
		if err != nil {
			log.Printf("error while marshalling Service to json: %v\n", err)
			continue
		}
		fmt.Println(string(data))
	}
}

func grab(service *Service, bannerSize int, connectTimeout, sslTimeout, readWriteTimeout time.Duration) (*Service, error) {
	service.Protocol = strings.ToLower(service.Protocol)
	if service.Protocol != "tcp" && service.Protocol != "udp" {
		return nil, errors.New("no such protocol")
	}

	// TODO support udp protocol
	if service.Protocol == "udp" {
		return service, nil
	}

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
		banner, _ := sendRecvTCP(service.IP, service.Port, handshake.Packet, bannerSize, connectTimeout, readWriteTimeout)
		if banner != nil {
			// http request sent to https
			var certificates [][]byte
			var httpsBanner []byte
			if handshake.Source == "http" && isHTTPSendToHTTPS(banner) {
				certificates, httpsBanner, _ = sendRecvTCPSSL(
					service.IP, service.Port, handshake.Packet, bannerSize, connectTimeout, sslTimeout, readWriteTimeout,
				)
			}

			if certificates != nil {
				service.SSL = true
				service.Certificates = certificates
			}
			service.Banner.Source = handshake.Source
			if httpsBanner != nil {
				banner = httpsBanner
			}
			service.Banner.Banner = banner

			return service, nil
		}
	}

	// ssl
	var banner []byte
	for _, handshake := range handshakes {
		service.Certificates, banner, _ = sendRecvTCPSSL(
			service.IP, service.Port, handshake.Packet, bannerSize, connectTimeout, sslTimeout, readWriteTimeout,
		)
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

func sendRecvTCPSSL(host string, port int, handshake []byte, bannerSize int, connectTimeout, sslTimeout,
	readWriteTimeout time.Duration) ([][]byte, []byte, error) {
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
