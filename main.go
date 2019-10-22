/* Wildcard Detection Tool HEAVILY based off of Owasp's Amass
 * And by heavily- straight rip - thanks @jeff_foley
 */

package main

import (
	"bufio"
	"fmt"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"os"
	"strings"
)

var debugmode bool

func main() {

	setDebugMode()

	pool := resolvers.SetupResolverPool([]string{"8.8.8.8"}, false, false)
	if pool == nil {
		return
	}

	// keep track of seen domains
	var known_domains_slice []string

	// read from stdin and process
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		// the sub domain
		name_str := sc.Text()
		var domain_str string

		// the root domain
		if known_domains_slice == nil {
			// the slice is empty
			domain_str = pool.SubdomainToDomain(name_str)
			if debugmode {
				fmt.Println("[*] Slice is nil. Adding ", domain_str)
			}
		} else {
			// slice is not empty, search slice to ration calls to SubdomainToDomain()
			for _, a_domain_str := range known_domains_slice {
				if strings.Contains(name_str, a_domain_str) {
					domain_str = a_domain_str
					if debugmode {
						fmt.Println("[*] Already seen:", domain_str)
					}
					break
				} else {
					domain_str = pool.SubdomainToDomain(name_str)
					if debugmode {
						fmt.Println("[*] New domain:", domain_str)
					}
					break
				}
			}
		}

		// add the domain to the known domains list
		known_domains_slice = addEntry(known_domains_slice, domain_str)
		if debugmode {
			fmt.Println("[*] known_domains_slice=", known_domains_slice)
		}

		// the request object for input to MatchesWildcard()
		req := &requests.DNSRequest{
			Name:   name_str,
			Domain: domain_str,
		}

		// Check if the sub domain is a wildcard
		if pool.MatchesWildcard(req) {
			if debugmode {
				fmt.Printf("Wildcard:%s (Domain:%s)\n", name_str, domain_str)
			}
		} else {
			if debugmode {
				fmt.Printf("Not Wildcard:%s (Domain:%s)\n", name_str, domain_str)
			}
			// print non-wildcards
			fmt.Println(name_str)
		}
	}

}

func addEntry(slice []string, domain string) []string {
	/*
	 * Append new domain to the entry
	 */

	if !sliceContains(slice, domain) {
		slice = append(slice, domain)
	}

	return slice
}

func sliceContains(slice []string, needle string) bool {
	/*
	 * Check if a slice contains a value
	 */

	for _, str := range slice {
		if str == needle {
			return true
		}
	}

	return false
}

func setDebugMode() {
	debug_str := os.Getenv("MYGODEBUG")

	if debug_str == "true" {
		fmt.Println("[*] Debug mode set to true.")
		debugmode = true
	} else {
		debugmode = false
	}
}
