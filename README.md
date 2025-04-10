# DNS Server in Go ![Lint and Test pipeline](https://github.com/blazskufca/dns_server_in_go/actions/workflows/ci.yaml/badge.svg)

This repository implements a (_mostly_ complete per [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)) forwarding and recursive DNS resolver.
```text
$ go run ./app/ -resolver 8.8.8.8:53 -recursive
Starting DNS forwarder with resolver: 8.8.8.8:53
time=2025-04-10T16:59:24.738+02:00 level=INFO msg="Starting DNS server with resolver" resolver="{IP:8.8.8.8 Port:53 Zone:}" listener=127.0.0.1:2053
time=2025-04-10T16:59:24.738+02:00 level=INFO msg="Bootstrapping root servers from upstream resolver"
time=2025-04-10T16:59:25.191+02:00 level=INFO msg="Root servers bootstrapped successfully" count=13
time=2025-04-10T16:59:25.191+02:00 level=INFO msg="TCP listener started" listener=127.0.0.1:2053
time=2025-04-10T16:59:29.626+02:00 level=INFO msg="Starting recursive resolution" domain=blazskufca.com type="A - Host address query"
time=2025-04-10T16:59:29.688+02:00 level=INFO msg="Found authoritative answer" domain=blazskufca.com answer_count=2
time=2025-04-10T16:59:29.688+02:00 level=INFO msg="Sent recursive response" to_address=127.0.0.1:47270 answer_count=2
```
```text
$ dig @127.0.0.1 -p 2053 +noedns +all blazskufca.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> @127.0.0.1 -p 2053 +noedns +all blazskufca.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25082
;; flags: qr aa ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;blazskufca.com.                        IN      A

;; ANSWER SECTION:
blazskufca.com.         300     IN      A       172.67.169.88
blazskufca.com.         300     IN      A       104.21.79.76

;; Query time: 59 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
;; WHEN: Thu Apr 10 16:59:29 CEST 2025
;; MSG SIZE  rcvd: 92
```

_Messages over `512` bytes:_

```text
$ go run ./app/ -resolver 8.8.8.8:53 -recursive
Starting DNS forwarder with resolver: 8.8.8.8:53
time=2025-04-10T17:01:59.043+02:00 level=INFO msg="Starting DNS server with resolver" resolver="{IP:8.8.8.8 Port:53 Zone:}" listener=127.0.0.1:2053
time=2025-04-10T17:01:59.043+02:00 level=INFO msg="Bootstrapping root servers from upstream resolver"
time=2025-04-10T17:01:59.452+02:00 level=INFO msg="Root servers bootstrapped successfully" count=13
time=2025-04-10T17:01:59.453+02:00 level=INFO msg="TCP listener started" listener=127.0.0.1:2053
time=2025-04-10T17:02:01.763+02:00 level=INFO msg="Starting recursive resolution" domain=google.com type="TXT - Text strings"
time=2025-04-10T17:02:01.921+02:00 level=INFO msg="Found authoritative answer" domain=google.com answer_count=12
time=2025-04-10T17:02:01.921+02:00 level=INFO msg="Sent recursive response" to_address=127.0.0.1:42398 answer_count=12
time=2025-04-10T17:02:01.922+02:00 level=INFO msg="Cache hit" domain=google.com type="TXT - Text strings"
```
```text
$ dig @127.0.0.1 -p 2053 +noedns +all google.com TXT
;; Truncated, retrying in TCP mode.

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> @127.0.0.1 -p 2053 +noedns +all google.com TXT
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29180
;; flags: qr aa ra; QUERY: 1, ANSWER: 12, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      TXT

;; ANSWER SECTION:
google.com.             3600    IN      TXT     "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
google.com.             3600    IN      TXT     "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
google.com.             3600    IN      TXT     "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
google.com.             3600    IN      TXT     "cisco-ci-domain-verification=479146de172eb01ddee38b1a455ab9e8bb51542ddd7f1fa298557dfa7b22d963"
google.com.             3600    IN      TXT     "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
google.com.             3600    IN      TXT     "onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef"
google.com.             3600    IN      TXT     "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
google.com.             3600    IN      TXT     "apple-domain-verification=30afIBcvSuDV2PLX"
google.com.             3600    IN      TXT     "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
google.com.             3600    IN      TXT     "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0"
google.com.             3600    IN      TXT     "v=spf1 include:_spf.google.com ~all"
google.com.             3600    IN      TXT     "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"

;; Query time: 0 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1) (TCP)
;; WHEN: Thu Apr 10 17:02:01 CEST 2025
;; MSG SIZE  rcvd: 995
```

## Features

- Recursive domain resolving
- Basing caching in recursive mode for already resolved queries which respect the response `TTL`
- Forwarding mode (upstream resolvers can be specified via program arguments)
- Message compression/decompression as described in [`RFC` 1035 section 4.1.4 - `Message compression`](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4)
- Both `UDP` (for messages up to `512` bytes) and `TCP` (for larger messages) listeners as described in [`RFC` 1035 section 4.2.1. `UDP usage`](https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1) and [`RFC` 1035 section 4.2.2. `TCP usage`](https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)

## What it currently lacks

- Support for [Extension Mechanisms for DNS (`EDNS0`)](https://datatracker.ietf.org/doc/html/rfc2671)
- Support for [DNS over TLS (`DoT`)](https://datatracker.ietf.org/doc/html/rfc7858) and [DNS over HTTPS (`DoH`)](https://datatracker.ietf.org/doc/html/rfc8484)
- _[And much more](https://powerdns.org/dns-camel/)_

## Acknowledgements

- [`RFC` 1034](https://datatracker.ietf.org/doc/html/rfc1034) and [`RFC` 1035](https://datatracker.ietf.org/doc/html/rfc1035)
- [Herding the DNS Camel](https://www.ietf.org/blog/herding-dns-camel)
- [Hello DNS](https://powerdns.org/hello-dns/)
- [DNS Camel](https://powerdns.org/dns-camel/)


