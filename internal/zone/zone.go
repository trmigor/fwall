package zone

import (
	"net"

	"github.com/trmigor/fwall/internal/policy"
)

type Zone struct {
	Name       string
	Interfaces []net.Interface
}

type ZoneMap map[*Zone]map[*Zone]*policy.Policy

func New(name string) *Zone {
	return &Zone{name, make([]net.Interface, 0)}
}

func NewZoneMap() ZoneMap {
	res := make(ZoneMap)
	return res
}
