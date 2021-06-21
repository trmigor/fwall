package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/trmigor/fwall/internal/connection"
	"github.com/trmigor/fwall/internal/policy"
	"github.com/trmigor/fwall/internal/zone"
)

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func parseClass(config []string, pos int) int {
	words := strings.Split(config[pos], " ")
	if len(words) != 2 && len(words) != 3 {
		panic("incorrect syntax: str " + fmt.Sprint(pos))
	}

	name := words[1]
	if _, ok := Classes[name]; ok {
		panic("class duplication: " + name)
	}

	matchAll := false
	if len(words) == 3 {
		switch words[2] {
		case "matchAll":
			matchAll = true
		case "matchAny":
		default:
			panic("incorrect syntax: str " + fmt.Sprint(pos))
		}
	}

	res := connection.New(name)
	res.MatchAll = matchAll

	pos++
	if matchAll {
		m_begin := ""
		m_end := "{ "
		for ; config[pos] != "!"; pos++ {
			if len(config[pos]) == 0 {
				continue
			}
			words := strings.Split(config[pos], " ")
			for i, word := range words {
				if i == len(words)-1 {
					m_end += word + " . "
				} else {
					m_begin += word + " "
				}
			}
			m_begin += ". "
		}
		m_begin = m_begin[:len(m_begin)-3]
		m_end = m_end[:len(m_end)-3]
		res.Matches = append(res.Matches, m_begin+" "+m_end+" }")
	} else {
		for ; config[pos] != "!"; pos++ {
			if len(config[pos]) == 0 {
				continue
			}
			words := strings.Split(config[pos], " ")
			if words[0] == "subclass" {
				if len(words) != 2 {
					panic("incorrect syntax: str " + fmt.Sprint(pos))
				}
				if _, ok := Classes[words[1]]; !ok {
					panic("no such class: " + words[1])
				}
				res.Matches = append(res.Matches, Classes[words[1]].Matches...)
			} else {
				res.Matches = append(res.Matches, config[pos])
			}

		}
	}

	Classes[name] = res
	return pos
}

func parseZone(config []string, pos int) int {
	words := strings.Split(config[pos], " ")
	if len(words) != 2 {
		panic("incorrect syntax: str " + fmt.Sprint(pos))
	}
	if _, ok := Zones[words[1]]; ok {
		panic("zone duplication: " + words[1])
	}
	Zones[words[1]] = zone.New(words[1])
	return pos
}

func parseInterface(config []string, pos int) int {
	words := strings.Split(config[pos], " ")
	if len(words) != 4 || words[2] != "in" {
		panic("incorrect syntax: str " + fmt.Sprint(pos))
	}
	inf, err := net.InterfaceByName(words[1])
	if err != nil {
		panic(err)
	}
	if _, ok := Zones[words[3]]; !ok {
		panic("no such zone: " + words[3])
	}
	Zones[words[3]].Interfaces = append(Zones[words[3]].Interfaces, *inf)
	Interfaces[inf.Name] = true
	return pos
}

func parsePolicy(config []string, pos int) int {
	words := strings.Split(config[pos], " ")
	if len(words) != 2 {
		panic("incorrect syntax: str " + fmt.Sprint(pos))
	}

	name := words[1]
	if _, ok := Policies[name]; ok {
		panic("policy duplication: " + name)
	}

	res := policy.New(words[1])

	pos++
	for ; config[pos] != "!"; pos++ {
		if len(config[pos]) == 0 {
			continue
		}
		words := strings.Split(config[pos], " ")
		if (len(words) != 3 && len(words) != 4) || words[0] != "for" {
			panic("incorrect syntax: str " + fmt.Sprint(pos))
		}

		if _, ok := Classes[words[1]]; !ok {
			panic("no such class: " + words[1])
		}
		class := Classes[words[1]]

		switch words[2] {
		case "accept":
			res.Map[class] = policy.Target{Type: policy.ACCEPT}
		case "drop":
			res.Map[class] = policy.Target{Type: policy.DROP}
		case "reject":
			info := "port-unreachable"
			if len(words) == 4 {
				info = words[3]
			}
			res.Map[class] = policy.Target{Type: policy.REJECT, Info: info}
		default:
			panic("unknown target: " + words[2])
		}
	}

	Policies[name] = res
	return pos
}

func parseZonePair(config []string, pos int) int {
	words := strings.Split(config[pos], " ")
	if len(words) != 4 {
		panic("incorrect syntax: str " + fmt.Sprint(pos))
	}

	if _, ok := Zones[words[1]]; !ok {
		panic("no such zone: " + words[1])
	}
	if _, ok := Zones[words[2]]; !ok {
		panic("no such zone: " + words[2])
	}
	if _, ok := Policies[words[3]]; !ok {
		panic("no such policy: " + words[3])
	}

	zone1 := Zones[words[1]]
	zone2 := Zones[words[2]]
	if zone1 == zone2 {
		panic("zones should be different: " + zone1.Name + " " + zone2.Name)
	}

	p := words[3]

	if _, ok := ZoneMap[zone1]; !ok {
		ZoneMap[zone1] = make(map[*zone.Zone]*policy.Policy)
	}
	ZoneMap[zone1][zone2] = Policies[p]
	return pos
}

func ParseConfig(path string) {
	config, err := readLines(path)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(config); i++ {
		words := strings.Split(config[i], " ")
		if len(words) < 2 {
			continue
		}
		switch words[0] {
		case "zone":
			i = parseZone(config, i)
		case "interface":
			i = parseInterface(config, i)
		case "policy":
			i = parsePolicy(config, i)
		case "class":
			i = parseClass(config, i)
		case "zone_pair":
			i = parseZonePair(config, i)
		default:
			panic("unknown command: " + words[0] + ", line " + fmt.Sprint(i))
		}
	}

	infs, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, inf := range infs {
		if _, ok := Interfaces[inf.Name]; !ok {
			Zones["SelfZone"].Interfaces = append(Zones["SelfZone"].Interfaces, inf)
		}
	}
}
