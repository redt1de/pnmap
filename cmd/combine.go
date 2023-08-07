package cmd

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/redt1de/pnmap/nmap"
	"github.com/spf13/cobra"
)

type hostMap map[string]nmap.Host

var hostmap hostMap

type fileslice []string

// var daFiles fileslice

func (i *fileslice) String() string {
	return fmt.Sprintf("%d", *i)
}
func (i *fileslice) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var infiles *[]string
var outfile *string
var onlyhosts *string
var hasports *bool
var onlyup *bool

// combineCmd represents the combine command
var combineCmd = &cobra.Command{
	Use:   "combine [options] <input file/s or *.xml> [more input file/s]",
	Short: "combine nmap XML files into one file.",
	Long:  `combine can be used to combine multiple nmap XML files into a single XML.`,
	Run: func(cmd *cobra.Command, args []string) {
		combine(args)
	},
}

func init() {
	rootCmd.AddCommand(combineCmd)

	outfile = combineCmd.Flags().StringP("out", "o", "nmap-combined.xml", "output file")
	onlyhosts = combineCmd.Flags().StringP("only-hosts", "O", "", "specify a file containing IPs, and only include those in the new XML")
	hasports = combineCmd.Flags().BoolP("has-ports", "p", false, "exclude hosts with no ports open, handy for -Pn scans.")
	onlyup = combineCmd.Flags().BoolP("only-up", "u", false, "only include hosts that are marked up")

}

func combine(args []string) {

	if len(args) < 1 {
		fmt.Println("[ERROR ] no input files specified")
		os.Exit(1)
	}
	//
	// HasPorts = *hasports
	hostmap = make(hostMap)
	final := nmap.NmapRun{}
	final.Verbose.Level = 0
	final.Debugging.Level = 0
	var tmpArgs []string
	var elapsed float32

	for _, infile := range args {
		matches, err := filepath.Glob(infile)
		if err != nil {
			fmt.Println(err)
		}
		for _, f := range matches {
			fmt.Println("[+] parsing", f)
			content, err := os.ReadFile(f)
			if err != nil {
				log.Fatal("Failed to read file:", err)
				continue
			}

			nRun, err := nmap.Parse(content)
			if err != nil {
				log.Fatal("Failed to parse XML:(", f, ") ", err)
				continue
			}
			final.Scanner = nRun.Scanner
			tmpArgs = append(tmpArgs, nRun.Args)

			// versions are set to whichever version is newest
			final.Version = strGreater(final.Version, nRun.Version)
			final.XMLOutputVersion = strGreater(final.XMLOutputVersion, nRun.XMLOutputVersion)

			// start time is set to the earliest/first scan run
			te := timeEarlier(nRun.Start, final.Start)
			if te == nRun.Start {
				final.Start = te
				final.StartStr = nRun.StartStr
			}

			final.ProfileName = nRun.ProfileName
			final.ScanInfo = nRun.ScanInfo

			// verbosity and debugging is set to whichever has the highest verbosity/dbugging level
			if nRun.Verbose.Level > final.Verbose.Level {
				final.Verbose.Level = nRun.Verbose.Level
			}

			if nRun.Debugging.Level > final.Debugging.Level {
				final.Debugging.Level = nRun.Debugging.Level
			}

			final.TaskBegin = append(final.TaskBegin, nRun.TaskBegin...)
			final.TaskProgress = append(final.TaskProgress, nRun.TaskProgress...)
			final.TaskEnd = append(final.TaskEnd, nRun.TaskEnd...)
			final.PreScripts = append(final.PreScripts, nRun.PreScripts...)
			final.PostScripts = append(final.PostScripts, nRun.PostScripts...)
			final.Targets = append(final.Targets, nRun.Targets...)

			// elapsed time is combined from all scans
			elapsed += nRun.RunStats.Finished.Elapsed

			// end time is the last time from all scans
			tl := timeLater(nRun.RunStats.Finished.Time, final.RunStats.Finished.Time)
			if tl == nRun.RunStats.Finished.Time {
				final.RunStats.Finished.Time = nRun.RunStats.Finished.Time
				final.RunStats.Finished.TimeStr = nRun.RunStats.Finished.TimeStr
			}

			for _, hst := range nRun.Hosts {
				if len(hostmap[hst.Addresses[0].Addr].Addresses) == 0 {
					hostmap[hst.Addresses[0].Addr] = hst
				} else {
					if hostmap[hst.Addresses[0].Addr].Status.State == "up" && hst.Status.State == "down" {
						continue
					}
					if hostmap[hst.Addresses[0].Addr].Status.State == "down" && hst.Status.State == "up" {
						hostmap[hst.Addresses[0].Addr] = hst
					}
					if hostmap[hst.Addresses[0].Addr].Status.State == "down" && hst.Status.State == "down" {
						continue
					}
					if hostmap[hst.Addresses[0].Addr].Status.State == "up" && hst.Status.State == "up" {
						if len(hostmap[hst.Addresses[0].Addr].Ports) > len(hst.Ports) {
							continue
						} else if len(hostmap[hst.Addresses[0].Addr].Ports) < len(hst.Ports) {
							hostmap[hst.Addresses[0].Addr] = hst
						} else {
							continue
						}

					}
				}
			}
		}
	}
	if *onlyhosts != "" {
		hostmap = GetOnlyHosts(hostmap, *onlyhosts)
	}

	// iterate the hosts map and add to final hosts results
	for k := range hostmap {
		// if onlyup flag is preset, check for up status
		if *onlyup && hostmap[k].Status.State != "up" {
			continue
		}

		final.Hosts = append(final.Hosts, hostmap[k])
	}

	final.RunStats.Finished.Elapsed = elapsed
	final.RunStats.Finished.Summary = "Parsed by brads nmap tool"
	final.RunStats.Finished.Exit = "success"

	// args are all combined so there is a record of each command run
	final.Args = strings.Join(tmpArgs, " /-/ ")

	// if hasports flag is present call func to remove hosts with no ports
	if *hasports {
		final.Hosts = withPorts(final.Hosts)
	}

	// count up,down,total hosts in final.hosts
	var up, down, total int
	for _, h := range final.Hosts {
		if h.Status.State == "up" {
			up++
		} else {
			down++
		}
		total++
	}

	final.RunStats.Hosts.Up = up
	final.RunStats.Hosts.Down = down
	final.RunStats.Hosts.Total = total

	fmt.Println("[+]", final.RunStats.Hosts.Up, "included in the new XML.")

	// pencil whip the xml header
	out := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap scan results, parsed by brads tool -->
`)

	// marshall xml using +++++ as indent which is then stripped out, otherwise ingest doesnt like the format.
	outbody, err := xml.MarshalIndent(final, "", "+++++")
	if err != nil {
		log.Fatal("Failed to marshall XML:", err)
	}
	out = append(out, outbody...)
	tmp := strings.ReplaceAll(string(out), "NmapRun", "nmaprun")
	tmp = strings.ReplaceAll(tmp, "+++++", "")

	err = os.WriteFile(*outfile, []byte(tmp), 0655)
	if err != nil {
		log.Fatal("Failed to write the file", *outfile+":", err)
	}

	fmt.Println("[+] Wrote ", len(out), "bytes to", *outfile)
}

func GetOnlyHosts(hostmap hostMap, onlyfile string) hostMap {
	var ret hostMap
	ret = make(hostMap)
	file, err := os.Open(onlyfile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if val, ok := hostmap[line]; ok {
			ret[line] = val
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return ret

}

// withPorts removes any hosts that do not have ports open.
func withPorts(hosts []nmap.Host) []nmap.Host {
	fmt.Println("[+] Filtering hosts with no ports")
	ret := []nmap.Host{}
	for _, h := range hosts {
		flg := false
		for _, p := range h.Ports {
			if p.State.State == "open" {
				flg = true
				ret = append(ret, h)
			}
		}
		if !flg {
			fmt.Println("[-] Skipping host with no ports:", h.Addresses[0].Addr)
		}
	}
	return ret
}

// timeEarlier compares two timestamps and returns whichever is earlier
func timeEarlier(a, b nmap.Timestamp) nmap.Timestamp {
	as := time2str(a)
	ai, err := strconv.ParseInt(as, 10, 64)
	if err != nil {
		fmt.Println("[ERROR] timeEarlier A:", err)
	}
	bs := time2str(b)
	bi, err := strconv.ParseInt(bs, 10, 64)
	if err != nil {
		fmt.Println("[ERROR] timeEarlier B:", err)
	}
	if ai < 0 && bi > 0 {
		return b
	}
	if bi < 0 && ai > 0 {
		return a
	}
	if bi < ai {
		return b
	}
	return a

}

// timeLater compares two timestamps and returns whichever is later
func timeLater(a, b nmap.Timestamp) nmap.Timestamp {
	as := time2str(a)
	ai, err := strconv.ParseInt(as, 10, 64)
	if err != nil {
		fmt.Println("[ERROR] timeEarlier A:", err)
	}
	bs := time2str(b)
	bi, err := strconv.ParseInt(bs, 10, 64)
	if err != nil {
		fmt.Println("[ERROR] timeEarlier B:", err)
	}
	if ai < 0 && bi > 0 {
		return b
	}
	if bi < 0 && ai > 0 {
		return a
	}
	if bi > ai {
		return b
	}
	return a

}

// strGreater is a util function that compares two float strings, and returns whichever is greater.
func strGreater(a, b string) string {
	ai, err := strconv.ParseFloat(a, 32)
	if err != nil {
		ai = 0
	}
	bi, err := strconv.ParseFloat(b, 32)
	if err != nil {
		bi = 0
	}
	return fmt.Sprintf("%.2f", math.Max(ai, bi))

}

// str2time converts a string containing a UNIX timestamp to to a time.Time.
func str2time(s string) (nmap.Timestamp, error) {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nmap.Timestamp{}, err
	}
	return nmap.Timestamp(time.Unix(ts, 0)), nil
}

// time2str formats the time.Time value as a UNIX timestamp string.
// XXX these might also need to be changed to pointers. See str2time and UnmarshalXMLAttr.
func time2str(t nmap.Timestamp) string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}
