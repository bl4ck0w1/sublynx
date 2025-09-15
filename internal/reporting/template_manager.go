package reporting

import (
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

type TemplateManager struct {
	templates map[string]*template.Template
	mu        sync.RWMutex
}

func NewTemplateManager() *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*template.Template),
	}
}

func (tm *TemplateManager) Register(name, tpl string, funcs template.FuncMap) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	t := template.New(name)
	if funcs != nil {
		t = t.Funcs(funcs)
	}
	parsed, err := t.Parse(tpl)
	if err != nil {
		return fmt.Errorf("parse %q: %w", name, err)
	}
	tm.templates[name] = parsed
	return nil
}

func (tm *TemplateManager) LoadDir(dir string, funcs template.FuncMap) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext != ".tmpl" && ext != ".gohtml" && ext != ".html" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %q: %w", path, err)
		}
		name := d.Name()
		t := template.New(name)
		if funcs != nil {
			t = t.Funcs(funcs)
		}
		parsed, err := t.Parse(string(b))
		if err != nil {
			return fmt.Errorf("parse %q: %w", path, err)
		}
		tm.templates[name] = parsed
		return nil
	})
	return err
}

func (tm *TemplateManager) Get(name string) (*template.Template, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t, ok := tm.templates[name]
	return t, ok
}

func (tm *TemplateManager) MustGet(name string) *template.Template {
	if t, ok := tm.Get(name); ok {
		return t
	}
	panic("template not found: " + name)
}
