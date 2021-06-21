package connection

type Class struct {
	Name     string
	MatchAll bool
	Matches  []string
}

func New(name string) *Class {
	return &Class{Name: name, MatchAll: false, Matches: make([]string, 0)}
}
