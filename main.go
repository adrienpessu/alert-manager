package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	githubToken := flag.String("token", "", "GitHub Token to use for authentication")

	flag.Parse()

	if *githubToken == "" {
		fmt.Println("Please provide a GitHub Token")
		return
	}

	fmt.Sprintf("GitHub current repository: %s", os.Getenv("GITHUB_REPOSITORY"))

}
