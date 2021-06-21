package policy

import (
	"github.com/trmigor/fwall/internal/connection"
)

type TargetType uint8

const (
	ACCEPT TargetType = iota
	DROP
	REJECT
)

type Target struct {
	Type TargetType
	Info string
}

type Policy struct {
	Name string
	Map  map[*connection.Class]Target
}

func New(name string) *Policy {
	return &Policy{name, make(map[*connection.Class]Target)}
}
