package main

import (
	"B2BinPay_API/api"
	"flag"
	"fmt"
	"log"
)

func startFlag() {
	test := flag.Bool("test", false, "Testing environment")
	flag.Parse()

	username := "teo@fanated.com"
	password := "7777777"
	client := api.NewB2BinPayClient(username, password, *test)

	attributes, err := client.Login()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Access token:", attributes.Access)
	fmt.Println("Access token expiration:", attributes.AccessExpiredAt)

	refreshToken := attributes.Refresh
	attributes, err = client.RefreshToken(refreshToken)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Access token:", attributes.Access)
	fmt.Println("Access token expiration:", attributes.AccessExpiredAt)
}
