package discovery

import "context"

type Options struct {
	Methods []string
	Depth   int
}

type Result struct {
	Subdomains []string
}

type Engine interface {
	Discover(ctx context.Context, domain string, opts Options) (Result, error)
	Close() error
}

func NewEngine(_ Options) (Engine, error) { return &nopEngine{}, nil }
type nopEngine struct{}
func (n *nopEngine) Discover(_ context.Context, _ string, _ Options) (Result, error) { return Result{}, nil }
func (n *nopEngine) Close() error                                                     { return nil }
