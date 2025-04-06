package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	resolverAddr := flag.String("resolver", "", "Address of the DNS resolver to forward queries to")
	servingAddress := flag.String("address", "127.0.0.1:2053", "Address of the DNS server")
	recursive := flag.Bool("recursive", false, "Recursively resolve DNS records")
	flag.Parse()

	if *resolverAddr == "" {
		log.Fatalln("Resolver address is required. Use -resolver flag.")
	}
	if *servingAddress == "" {
		log.Fatalln("Server address is required. Use -address flag.")
	}

	fmt.Println("Starting DNS forwarder with resolver:", *resolverAddr)

	dns, closeCon, err := New(*servingAddress, *resolverAddr, *recursive, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer closeCon()

	dns.Start()
}
