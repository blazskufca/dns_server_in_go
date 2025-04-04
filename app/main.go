package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	resolverAddr := flag.String("resolver", "", "Address of the DNS resolver to forward queries to")
	flag.Parse()

	if *resolverAddr == "" {
		log.Fatalln("Resolver address is required. Use --resolver flag.")
	}

	fmt.Println("Starting DNS forwarder with resolver:", *resolverAddr)

	dns, closeCon, err := New("127.0.0.1:2053", *resolverAddr, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer closeCon()

	dns.Start()
}
