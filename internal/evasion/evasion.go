package evasion

type Options struct {
	Techniques []string
	Stealth    bool
}

type Manager interface {
	Apply(req any) any
	Close() error
}

func NewManager(_ Options) (Manager, error) { return &nopManager{}, nil }
type nopManager struct{}
func (n *nopManager) Apply(req any) any { return req }
func (n *nopManager) Close() error      { return nil }
