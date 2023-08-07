package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/redt1de/pnmap/nmap"
	"github.com/spf13/cobra"
)

var outpath *string
var byport *bool
var portnumMap map[int][]string
var serviceMap map[string][]string

// groupCmd represents the group command
var groupCmd = &cobra.Command{
	Use:   "group [options] <input file/s or *.xml> [more input file/s]",
	Short: "create lists of IP addresses grouped by port/service",
	Long:  `create a directory containing lists of ips, based on the service name identified by nmap`,
	Run: func(cmd *cobra.Command, args []string) {
		group(args)
	},
}

func init() {
	rootCmd.AddCommand(groupCmd)
	outpath = groupCmd.Flags().StringP("out-path", "o", "./out", "output directory")
	byport = groupCmd.Flags().BoolP("portnum", "p", false, "group by port number instead of service name")
}

func group(args []string) {
	if len(args) < 1 {
		fmt.Println("[ERROR ] no input files specified")
		os.Exit(1)
	}
	portnumMap = make(map[int][]string)
	serviceMap = make(map[string][]string)

	for _, infile := range args {
		matches, err := filepath.Glob(infile)
		if err != nil {
			fmt.Println(err)
		}
		for _, f := range matches {
			content, err := os.ReadFile(f)
			if err != nil {
				log.Fatal("Failed to read file:", err)
				continue
			}

			nRun, err := nmap.Parse(content)
			if err != nil {
				log.Fatal("Failed to parse XML:", err)
				continue
			}
			for _, hst := range nRun.Hosts {
				for _, prt := range hst.Ports {
					serviceMap[prt.Service.Name] = append(serviceMap[prt.Service.Name], hst.Addresses[0].Addr+":"+strconv.Itoa(prt.PortId))
					portnumMap[prt.PortId] = append(portnumMap[prt.PortId], hst.Addresses[0].Addr+":"+strconv.Itoa(prt.PortId))
				}
			}

		}
	}
	if !DirExist(*outpath) {
		err := CreatePathAll(*outpath)
		if err != nil {
			fmt.Println("[ERROR] failed to create output directory:", *outpath)
			os.Exit(1)
		}
	}

	if *byport {
		for pnum, ips := range portnumMap {
			i := unique(ips)
			fmt.Println("port number", strconv.Itoa(pnum)+":", len(i), "hosts")
			WriteLines(i, *outpath+"/"+strconv.Itoa(pnum)+".ips")
		}
	} else {
		for serv, ips := range serviceMap {
			i := unique(ips)
			fmt.Println("service", serv+":", len(i), "hosts")
			WriteLines(i, *outpath+"/"+serv+".ips")
		}
	}
}
