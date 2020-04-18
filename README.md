# gwdomains

Get (rid of) Wildcard Domains

## Install

go get github.com/thelikes/gwdomains

## Run

This tool takes a list of potential sub domains and filters out only legitimate
domains. For use with tools like altdns, dnsgen, and syborg.

### How to

#### Steps

1. Brute force sub domains (knock,amass,fierce,subfinder,etc)
2. Run a mutator (dnsgen,syborg,etc)
3. Resolve the mutations
4. Feed gwdomains the mutated sub domains

#### Run

`cat mutated.txt | gwdomains`

#### Debug

Verbose output:

`cat mutated.txt |MYGODEBUG=true gwdomains`

## Thanks

HuG3 thanks to OWASP Amass
