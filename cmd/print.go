package main

import (
	"fmt"
	"os"

	"github.com/trmigor/fwall/internal/policy"
)

func printBaseChainIncoming(tabs string) string {
	res := tabs + "chain base_incoming {\n"
	tabs += "  "

	res += tabs + "type filter hook input priority 0; policy drop;\n\n"

	for zone1, m := range ZoneMap {
		for zone2, pol := range m {
			if zone2.Name == "SelfZone" {
				for _, inf := range zone1.Interfaces {
					res += tabs + "meta iifname \"" + inf.Name + "\" jump p_" + pol.Name + "\n"
				}
			}
		}
	}
	for _, inf := range Zones["SelfZone"].Interfaces {
		res += tabs + "meta iifname \"" + inf.Name + "\" accept\n"
	}

	res += tabs[2:] + "}\n"
	return res
}

func printBaseChainOutgoing(tabs string) string {
	res := tabs + "chain base_outgoing {\n"
	tabs += "  "

	res += tabs + "type filter hook output priority 0; policy drop;\n\n"

	if m, ok := ZoneMap[SelfZone]; ok {
		for zone2, pol := range m {
			if zone2.Name == "SelfZone" {
				for _, inf := range zone2.Interfaces {
					res += tabs + "meta oifname \"" + inf.Name + "\" jump p_" + pol.Name + "\n"
				}
			}
		}
	}

	for _, inf := range Zones["SelfZone"].Interfaces {
		res += tabs + "meta oifname \"" + inf.Name + "\" accept\n"
	}

	res += tabs[2:] + "}\n"
	return res
}

func printBaseChainForward(tabs string) string {
	res := tabs + "chain base_forward {\n"
	tabs += "  "

	res += tabs + "type filter hook forward priority 0; policy drop;\n\n"

	for zone1, m := range ZoneMap {
		for zone2, pol := range m {
			if zone1.Name != "SelfZone" && zone2.Name != "SelfZone" {
				for _, inf1 := range zone1.Interfaces {
					for _, inf2 := range zone2.Interfaces {
						res += tabs + "meta iifname . meta oifname \"" + inf1.Name + "\" . \"" + inf2.Name + "\" jump p_" + pol.Name + "\n"
					}
				}
			}
		}
	}

	for _, zone := range Zones {
		for _, inf1 := range zone.Interfaces {
			for _, inf2 := range zone.Interfaces {
				if inf1.Name != inf2.Name {
					res += tabs + "meta iifname . meta oifname \"" + inf1.Name + "\" . \"" + inf2.Name + "\" accept\n"
				}
			}
		}
	}

	res += tabs[2:] + "}\n"
	return res
}

func printRegularChain(pol *policy.Policy, tabs string) string {
	res := "\n" + tabs + "chain p_" + pol.Name + " {\n"
	tabs += "  "

	for class, target := range pol.Map {
		t := ""
		switch target.Type {
		case policy.ACCEPT:
			t = "accept"
		case policy.DROP:
			t = "drop"
		case policy.REJECT:
			t = "reject with icmpx type " + target.Info
		}
		for _, match := range class.Matches {
			res += tabs + match + " " + t + "\n"
		}
		res += "\n"
	}

	res += tabs[2:] + "}\n"
	return res
}

func PrintConfig() string {
	res := "flush ruleset\n\n"
	res += "table inet fwall {\n"
	tabs := "  "

	res += printBaseChainIncoming(tabs) + "\n"
	res += printBaseChainOutgoing(tabs) + "\n"
	res += printBaseChainForward(tabs)

	for _, pol := range Policies {
		res += printRegularChain(pol, tabs)
	}

	res += "}\n"
	return res
}

func Save(path string) {
	out, err := os.OpenFile(path, os.O_RDWR|os.O_TRUNC, os.FileMode(0755))
	if err != nil {
		panic(err)
	}

	for n, p := range Classes {
		fmt.Fprintf(out, "class %v ", n)
		fmt.Fprintf(out, "matchAny\n")
		for _, m := range p.Matches {
			fmt.Fprintf(out, "%v\n", m)
		}
		fmt.Fprintf(out, "!\n\n")
	}

	for n, p := range Policies {
		fmt.Fprintf(out, "policy %v\n", n)
		for c, t := range p.Map {
			typ := ""
			switch t.Type {
			case policy.ACCEPT:
				typ = "accept"
			case policy.DROP:
				typ = "drop"
			case policy.REJECT:
				typ = "reject"
			}
			fmt.Fprintf(out, "for %v %v", c.Name, typ)
			if t.Info != "" {
				fmt.Fprintf(out, " %v\n", t.Info)
			} else {
				fmt.Fprintf(out, "\n")
			}
		}
		fmt.Fprintf(out, "!\n\n")
	}

	for n, p := range Zones {
		if n == "SelfZone" {
			continue
		}
		fmt.Fprintf(out, "zone %v\n\n", n)
		for _, inf := range p.Interfaces {
			fmt.Fprintf(out, "interface %v in %v\n\n", inf.Name, n)
		}
	}

	for zone1, m := range ZoneMap {
		for zone2, policy := range m {
			fmt.Fprintf(out, "zone_pair %v %v %v\n\n", zone1.Name, zone2.Name, policy.Name)
		}
	}
}
