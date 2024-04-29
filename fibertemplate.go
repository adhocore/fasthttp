// Copied from https://github.com/gofiber/template
// See license https://github.com/gofiber/template/blob/master/LICENSE
package fasthttp

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	fspath "path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const LayoutEmbed = "embed"

type Render struct {
	fs         http.FileSystem
	t          *template.Template
	fns        template.FuncMap
	mu         sync.RWMutex
	Directory  string
	Extension  string
	Reload, ok bool
}

var ErrEmbedCalled = errors.New("embed called directly")

func Renderer(dir, ext string, reload bool, fs http.FileSystem) *Render {
	r := &Render{
		fs: fs,
		fns: template.FuncMap{
			LayoutEmbed: func() error { return ErrEmbedCalled },
		},
		Directory: dir,
		Extension: ext,
		Reload:    reload,
	}
	return r
}

func (r *Render) EmbedFS(fs *embed.FS) *Render {
	r.fs = http.FS(fs)
	return r
}

func (r *Render) AddFunc(f string, fn any) *Render {
	r.fns[f] = fn
	return r
}

func (e *Render) Load() *Render {
	if !e.Reload && e.ok {
		return e
	}

	e.t = template.New(e.Directory)
	e.t.Funcs(e.fns)

	walkFn := func(path string, info fs.FileInfo, err error) error {
		// Return error if exist
		if err != nil {
			return err
		}

		// Skip file if it's a directory or has no file info
		if info == nil || info.IsDir() {
			return nil
		}

		// Skip file if it does not equal the given template Extension
		if len(e.Extension) >= len(path) || path[len(path)-len(e.Extension):] != e.Extension {
			return nil
		}

		// Get the relative file path
		// ./views/html/index.tmpl -> index.tmpl
		rel, err := filepath.Rel(e.Directory, path)
		if err != nil {
			return err
		}

		// Reverse slashes '\' -> '/' and ext
		name := strings.TrimSuffix(filepath.ToSlash(rel), e.Extension)
		buf, err := readFile(path, e.fs)
		if err != nil {
			return err
		}

		// Create new template associated with the current one
		// This enable use to invoke other templates {{ template .. }}
		_, err = e.t.New(name).Parse(string(buf))
		return err
	}

	if e.fs != nil {
		walker(e.fs, e.Directory, walkFn)
	} else {
		filepath.Walk(e.Directory, walkFn)
	}
	e.ok = true
	return e
}

func (e *Render) Render(out io.Writer, name string, binding Map, layouts ...string) (err error) {
	e.mu.RLock()
	if e.Reload {
		e.Load()
	}
	tmpl := e.t.Lookup(name)
	e.mu.RUnlock()

	if tmpl == nil {
		return errors.New("template not found: " + name)
	}

	render := renderer(out, binding, *tmpl, func() error { return ErrEmbedCalled })
	if len(layouts) == 0 {
		return render()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// construct a nested render function to embed templates in layouts
	for _, ln := range layouts {
		if ln == "" {
			break
		}
		lay := e.t.Lookup(ln)
		if lay == nil {
			return fmt.Errorf("render: LayoutName %s does not exist", ln)
		}
		render = renderer(out, binding, *lay, render)
	}
	return render()
}

func readFile(path string, fs http.FileSystem) ([]byte, error) {
	if fs != nil {
		file, err := fs.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(file)
	}
	return os.ReadFile(path)
}

func walker(fs http.FileSystem, root string, walkFn filepath.WalkFunc) error {
	info, err := stat(fs, root)
	if err != nil {
		return walkFn(root, nil, err)
	}
	return walk(fs, root, info, walkFn)
}

func stat(fs http.FileSystem, name string) (os.FileInfo, error) {
	f, err := fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func walk(fs http.FileSystem, path string, info os.FileInfo, walkFn filepath.WalkFunc) error {
	err := walkFn(path, info, nil)
	if err != nil {
		if info.IsDir() && err == filepath.SkipDir {
			return nil
		}
		return err
	}

	if !info.IsDir() {
		return nil
	}

	names, err := readDirNames(fs, path)
	if err != nil {
		return walkFn(path, info, err)
	}

	for _, name := range names {
		filename := fspath.Join(path, name)
		fileInfo, err := stat(fs, filename)
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			err = walk(fs, filename, fileInfo, walkFn)
			if err != nil {
				if !fileInfo.IsDir() || err != filepath.SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

func readDirNames(fs http.FileSystem, dirname string) ([]string, error) {
	fis, err := readDir(fs, dirname)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(fis))
	for i := range fis {
		names[i] = fis[i].Name()
	}
	sort.Strings(names)
	return names, nil
}

func readDir(fs http.FileSystem, name string) ([]os.FileInfo, error) {
	f, err := fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdir(0)
}

func renderer(w io.Writer, bind any, tmpl template.Template, embedFunc func() error) func() error {
	return func() error {
		tmpl.Funcs(template.FuncMap{LayoutEmbed: embedFunc})
		return tmpl.Execute(w, bind)
	}
}
