package main

import (
	"fmt"
	"os"

	"github.com/trmigor/fwall/internal/connection"
	"github.com/trmigor/fwall/internal/policy"
	"github.com/trmigor/fwall/internal/zone"
)

var (
	ZoneMap    zone.ZoneMap
	SelfZone   *zone.Zone
	Zones      map[string]*zone.Zone
	Policies   map[string]*policy.Policy
	Classes    map[string]*connection.Class
	Interfaces map[string]bool

	cmdList []string
)

func printAllStructs() {
	fmt.Println("Zones:")
	for n, p := range Zones {
		fmt.Printf("%v [", n)
		for i, inf := range p.Interfaces {
			fmt.Printf("%v", inf.Name)
			if i != len(p.Interfaces)-1 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("]\n")
	}

	fmt.Println("\nPolicies:")
	for n, p := range Policies {
		fmt.Printf("%v [\n", n)
		for c, t := range p.Map {
			fmt.Printf("%v: %v,\n", c.Name, t)
		}
		fmt.Printf("]\n")
	}

	fmt.Println("\nClasses:")
	for n, p := range Classes {
		fmt.Printf("%v ", n)
		if p.MatchAll {
			fmt.Printf("matchAll: ")
		} else {
			fmt.Printf("matchAny: ")
		}
		fmt.Printf("[")
		for i, m := range p.Matches {
			fmt.Printf("\"%v\"", m)
			if i != len(p.Matches)-1 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("]\n")
	}

	fmt.Println("\nZoneMap:")
	for zone1, m := range ZoneMap {
		for zone2, policy := range m {
			fmt.Printf("%v %v %v\n", zone1.Name, zone2.Name, policy.Name)
		}
	}
}

func init() {
	ZoneMap = zone.NewZoneMap()

	Zones = make(map[string]*zone.Zone)
	SelfZone = zone.New("SelfZone")
	Zones["SelfZone"] = SelfZone

	Policies = make(map[string]*policy.Policy)
	Classes = make(map[string]*connection.Class)
	Interfaces = make(map[string]bool)
}

func main() {
	args := os.Args[1:]

	ParseConfig("conf.fwall")

	cmdList = []string{
		"help",
		"config",
		"shell",
		"gui",
		"add",
		"remove",
		"rename",
		"list",
		"show",
		"insert",
		"parse",
		"apply",
	}

	switch args[0] {
	case "help":
		handleHelp()
	case "config":
		handleConfig()
	case "shell":
		handleShell()
	case "gui":
		handleGUI()
	case "add":
		handleAdd(args)
	case "remove":
		handleRemove(args)
	case "rename":
		handleRename(args)
	case "list":
		handleList(args)
	case "show":
		handleShow(args)
	case "insert":
		handleInsert()
	case "parse":
		handleParse()
	case "apply":
		handleApply()
	case "flush":
		handleFlush()
	default:
		handleDefault()
	}

	//res := PrintConfig()
	//fmt.Printf("\n%v", res)
	Save("conf.fwall")
}
