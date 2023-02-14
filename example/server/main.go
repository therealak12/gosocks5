package main

import (
	"log"

	"github.com/therealak12/gosocks5"
)

func main() {
	log.SetFlags(log.Lshortfile)

	if err := gosocks5.NewServer("", 1080).ListenAndServe(); err != nil {
		log.Printf("ListenAndServe returned err: %v", err)
	}
}
