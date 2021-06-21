package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/trmigor/fwall/internal/connection"
	"github.com/trmigor/fwall/internal/policy"
	"github.com/trmigor/fwall/internal/zone"
)

func handleHelp() {
	fmt.Println("Help message:")
	fmt.Printf("List of commands: %v\n", cmdList)
}

func handleConfig() {
	cmd := exec.Command("vim", "conf.fwall")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
}

func handleShell() {
	fmt.Println("fwall - zone-based front-end firewall interface.")
	fmt.Println("Version 0.0.7")
	fmt.Println("")

	fmt.Print(">> ")
	for {
		line := ""
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			line = scanner.Text()
		}
		words := strings.Split(line, " ")

		if words[0] == "exit" {
			break
		}

		switch words[0] {
		case "help":
			handleHelp()
		case "config":
			handleConfig()
		case "shell":
			handleShell()
		case "gui":
			handleGUI()
		case "add":
			handleAdd(words)
		case "remove":
			handleRemove(words)
		case "rename":
			handleRename(words)
		case "list":
			handleList(words)
		case "show":
			handleShow(words)
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

		fmt.Print(">> ")
	}
}

func handleGUI() {
	http.Handle("/", http.FileServer(http.Dir("./assets")))
	http.ListenAndServe(":8080", nil)
}

func handleAdd(args []string) {
	switch args[1] {
	case "class":
		cl := &connection.Class{}
		cl.Name = args[2]
		cl.MatchAll = args[4] == "matchAll"
		Classes[cl.Name] = cl
	case "rule":
		cl := Classes[args[3]]
		match := strings.Join(args[5:], " ")
		cl.Matches = append(cl.Matches, match)
	case "policy":
		pol := &policy.Policy{}
		pol.Name = args[2]
		Policies[pol.Name] = pol
	case "answer":
		pol := Policies[args[3]]
		cl := Classes[args[5]]
		ans := args[7:]
		switch ans[0] {
		case "accept":
			t := policy.Target{policy.ACCEPT, ""}
			pol.Map[cl] = t
		case "drop":
			t := policy.Target{policy.DROP, ""}
			pol.Map[cl] = t
		case "reject":
			t := policy.Target{policy.REJECT, ans[1]}
			pol.Map[cl] = t
		default:
			handleDefault()
		}
	case "zone":
		z := &zone.Zone{}
		z.Name = args[2]
		Zones[z.Name] = z
	case "interface":
		inf, err := net.InterfaceByName(args[2])
		if err != nil {
			panic(err)
		}
		z := Zones[args[4]]
		z.Interfaces = append(z.Interfaces, *inf)
	case "zone_pair":
		z1 := Zones[args[2]]
		z2 := Zones[args[3]]
		pol := Policies[args[5]]
		if _, ok := ZoneMap[z1]; !ok {
			ZoneMap[z1] = make(map[*zone.Zone]*policy.Policy)
		}
		ZoneMap[z1][z2] = pol
	default:
		handleDefault()
	}
}

func handleRemove(args []string) {
	switch args[1] {
	case "class":
		delete(Classes, args[2])
	case "rule":
		num := 0
		fmt.Sscanf(args[2], "%v", &num)
		cl := Classes[args[4]]
		cl.Matches = append(cl.Matches[:num], cl.Matches[num+1:]...)
	case "policy":
		delete(Policies, args[2])
	case "answer":
		cl := Classes[args[3]]
		pol := Policies[args[5]]
		delete(pol.Map, cl)
	case "zone":
		delete(Zones, args[2])
	case "interface":
		inf, err := net.InterfaceByName(args[2])
		if err != nil {
			panic(err)
		}
		z := Zones[args[4]]
		num := 0
		for n, inter := range z.Interfaces {
			if inter.Name == inf.Name {
				num = n
			}
		}
		z.Interfaces = append(z.Interfaces[:num], z.Interfaces[num+1:]...)
	case "zone_pair":
		z1 := Zones[args[2]]
		z2 := Zones[args[3]]
		if _, ok := ZoneMap[z1]; ok {
			delete(ZoneMap[z1], z2)
		}
	default:
		handleDefault()
	}
}

func handleRename(args []string) {
	switch args[1] {
	case "class":
		Classes[args[4]] = Classes[args[2]]
		delete(Classes, args[2])
	case "policy":
		Policies[args[4]] = Policies[args[2]]
		delete(Policies, args[2])
	case "zone":
		Zones[args[4]] = Zones[args[2]]
		delete(Zones, args[2])
	default:
		handleDefault()
	}
}

func handleList(args []string) {
	switch args[1] {
	case "classes":
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
	case "policies":
		fmt.Println("\nPolicies:")
		for n, p := range Policies {
			fmt.Printf("%v [\n", n)
			for c, t := range p.Map {
				fmt.Printf("%v: %v,\n", c.Name, t)
			}
			fmt.Printf("]\n")
		}
	case "zones":
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
	case "zone_pairs":
		fmt.Println("\nZoneMap:")
		for zone1, m := range ZoneMap {
			for zone2, policy := range m {
				fmt.Printf("%v %v %v\n", zone1.Name, zone2.Name, policy.Name)
			}
		}
	default:
		handleDefault()
	}
}

func handleShow(args []string) {
	switch args[1] {
	case "class":
		p := Classes[args[2]]
		fmt.Printf("%v ", p.Name)
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
	case "policy":
		p := Policies[args[2]]
		fmt.Printf("%v [\n", p.Name)
		for c, t := range p.Map {
			fmt.Printf("%v: %v,\n", c.Name, t)
		}
		fmt.Printf("]\n")
	case "zone":
		p := Zones[args[2]]
		fmt.Printf("%v [", p.Name)
		for i, inf := range p.Interfaces {
			fmt.Printf("%v", inf.Name)
			if i != len(p.Interfaces)-1 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("]\n")
	default:
		handleDefault()
	}
}

func handleInsert() {

}

func handleParse() {
	fmt.Printf("%v\n", PrintConfig())
}

func handleApply() {
	res := PrintConfig()
	out, err := os.OpenFile("nft.conf", os.O_CREATE|os.O_RDWR, os.FileMode(0755))
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(out, "%v\n", res)
}

func handleFlush() {
	out, err := os.OpenFile("nft.conf", os.O_TRUNC|os.O_RDWR, os.FileMode(0755))
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(out, "flush ruleset\n")
}

func handleDefault() {
	fmt.Println("Syntax error")
}
