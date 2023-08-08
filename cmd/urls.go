/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/spf13/cobra"
)

var extraDNS *string

// urlsCmd represents the urls command
var urlsCmd = &cobra.Command{
	Use:   "urls",
	Short: "Parses an Nmap XML file and returns a list of URLs, by ip:port and hostname:port",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		urls(args)
	},
}

func init() {
	rootCmd.AddCommand(urlsCmd)
	extraDNS = urlsCmd.Flags().StringP("dns", "d", "", "specify a file containing DNS info in the format IP:domain1,domain2")
}

func urls(args []string) {

	if len(args) < 1 {
		fmt.Println("[ERROR ] no input files specified")
		os.Exit(1)
	}

	var out []string
	for _, infile := range args {
		matches, err := filepath.Glob(infile)
		if err != nil {
			fmt.Println(err)
		}
		for _, f := range matches {

			nRun := nmap.Run{}
			err := nRun.FromFile(f)
			if err != nil {
				log.Fatal("Failed to parse XML:", err)
				continue
			}
			for _, hst := range nRun.Hosts {
				for _, p := range hst.Ports {
					test, _ := json.Marshal(p.Service)
					chk := strings.ToLower(string(test))
					if strings.Contains(chk, "http") || strings.Contains(chk, "tls") {
						scheme := "http://"
						if strings.Contains(chk, "https") || strings.Contains(chk, "ssl") || strings.Contains(chk, "tls") || strings.Contains(chk, "tls") {
							scheme = "https://"
						}
						out = append(out, scheme+hst.Addresses[0].Addr+":"+strconv.Itoa(int(p.ID)))

						for _, hn := range hst.Hostnames {
							out = append(out, scheme+hn.Name+":"+strconv.Itoa(int(p.ID)))
						}

						if *extraDNS != "" {
							lst, err := ReadLines(*extraDNS)
							if err != nil {
								log.Fatal(err)
							}
							for _, l := range lst {
								tmp := strings.Split(l, ":")
								if len(tmp) < 2 {
									continue
								}
								ip := tmp[0]
								if ip != hst.Addresses[0].Addr {
									continue
								}
								doms := tmp[1]
								for _, dom := range strings.Split(doms, ",") {
									out = append(out, scheme+dom+":"+strconv.Itoa(int(p.ID)))
								}

							}

						}

					}
				}
			}

		}
	}
	for _, ip := range unique(out) {
		fmt.Println(ip)
	}

}
