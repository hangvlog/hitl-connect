package main

import (
	"flag"
	"fmt"
	"hitl.local/connect/internal/desktopupgrade"
	"os"
)

func main() {
	dir := flag.String("dir", "", "exact desktop install directory")
	closePanels := flag.Bool("close-panels", false, "close verified same-user desktop panels after consent")
	flag.Parse()
	if flag.NArg() != 0 {
		os.Exit(20)
	}
	code, err := desktopupgrade.Prepare(*dir, *closePanels)
	if err != nil {
		fmt.Fprintln(os.Stdout, err)
	}
	os.Exit(code)
}
