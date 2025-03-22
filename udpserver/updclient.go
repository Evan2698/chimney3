package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// Resolve the address to listen on
	addr, err := net.ResolveUDPAddr("udp", ":8080")
	if err != nil {
		fmt.Println("Error resolving address:", err)
		os.Exit(1)
	}

	// Create a UDP connection
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("UDP server listening on port 8080")

	buffer := make([]byte, 1024)

	for {
		// Read from the UDP connection
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP connection:", err)
			continue
		}

		fmt.Printf("Received %s from %s\n", string(buffer[:n]), clientAddr)

		// Echo the message back to the client
		_, err = conn.WriteToUDP(buffer[:n], clientAddr)
		if err != nil {
			fmt.Println("Error writing to UDP connection:", err)
			continue
		}
	}
}
