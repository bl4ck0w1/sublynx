package validation

import "context"

type Options struct {
	Methods []string
}

type Result struct {
	Findings int
}

type Engine interface {
	Validate(ctx context.Context, domain string, subdomains []string, opts Options) (Result, error)
	Close() error
}

func NewEngine(_ Options) (Engine, error) { return &nopEngine{}, nil }
type nopEngine struct{}
func (n *nopEngine) Validate(_ context.Context, _ string, _ []string, _ Options) (Result, error) {
	return Result{}, nil
}
func (n *nopEngine) Close() error { return nil }
