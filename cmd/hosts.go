/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/spf13/cobra"
)

var hasports2 *bool

// hostsCmd represents the hosts command
var hostsCmd = &cobra.Command{
	Use:   "hosts [options] <input file/s or *.xml> [more input file/s]",
	Short: "list all ips for up hosts",
	Long:  `just list all ips marked as UP in an Nmap XML file`,
	Run: func(cmd *cobra.Command, args []string) {
		hosts(args)
	},
}

func init() {
	rootCmd.AddCommand(hostsCmd)
	hasports2 = hostsCmd.Flags().BoolP("has-ports", "p", false, "exclude hosts with no ports open, handy for -Pn scans.")

}

func hosts(args []string) {
	if len(args) < 1 {
		fmt.Println("[ERROR ] no input files specified")
		os.Exit(1)
	}

	// HasPorts = *hasports
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
				if hst.Status.State == "up" {
					if *hasports2 && len(hst.Ports) < 1 {
						continue
					}
				}
				out = append(out, hst.Addresses[0].Addr)
			}

		}
	}
	for _, ip := range unique(out) {
		fmt.Println(ip)
	}

}
