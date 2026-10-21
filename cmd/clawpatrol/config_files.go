package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
)

// dashboardConfigFile is the file /api/config/apply appends to in
// directory mode when the request names none. The 90- prefix sorts it
// after hand-written files.
const dashboardConfigFile = "90-dashboard.hcl"

// newConfigFileExecBits are cleared from the directory's mode to get
// the mode of a config file the dashboard creates.
const newConfigFileExecBits fs.FileMode = 0o111

var errUnknownConfigFile = errors.New("unknown config file")

// configInvalidError wraps a candidate config that failed to load, so
// handlers can answer 400 rather than 500.
type configInvalidError struct{ err error }

func (e *configInvalidError) Error() string { return e.err.Error() }
func (e *configInvalidError) Unwrap() error { return e.err }

type configFileInfo struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
	Size     int    `json:"size"`
}

type configChange struct {
	Name    string
	Content []byte
}

func configIsDir(cfgPath string) bool {
	st, err := os.Stat(cfgPath)
	return err == nil && st.IsDir()
}

// configFiles lists the files the loader reads from cfgPath, in load
// order: the file itself, or the directory's `*.hcl` files.
func configFiles(cfgPath string) ([]configFileInfo, error) {
	dir, names := filepath.Dir(cfgPath), []string{filepath.Base(cfgPath)}
	if configIsDir(cfgPath) {
		var err error
		if names, err = config.DirFileNames(cfgPath); err != nil {
			return nil, err
		}
		dir = cfgPath
	}
	out := make([]configFileInfo, 0, len(names))
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, configFileInfo{Name: name, Revision: revisionForBytes(b), Size: len(b)})
	}
	return out, nil
}

// resolveConfigFile maps a requested file name to the name and path it
// stands for. An empty name means the config file itself, or in
// directory mode the dashboard's own file.
func resolveConfigFile(cfgPath, name string) (string, string, error) {
	if !configIsDir(cfgPath) {
		base := filepath.Base(cfgPath)
		if name != "" && name != base {
			return "", "", fmt.Errorf("%w %q: the config is the single file %q", errUnknownConfigFile, name, base)
		}
		return base, cfgPath, nil
	}
	if name == "" {
		name = dashboardConfigFile
	}
	if !config.IsDirConfigFileName(name) {
		return "", "", fmt.Errorf("%w %q: names a `*.hcl` file directly in the config directory", errUnknownConfigFile, name)
	}
	return name, filepath.Join(cfgPath, name), nil
}

// planConfigAppend returns the changes that append snippet to target
// (whose content is current). In directory mode, generated `profile`
// credential lists are first folded into the files declaring those
// profiles. The target comes first: it carries any new declarations
// the profile files then reference.
func planConfigAppend(cfgPath, target string, current []byte, snippet string) ([]configChange, error) {
	var profileChanges []configChange
	if configIsDir(cfgPath) {
		names, err := config.DirFileNames(cfgPath)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if name == target {
				continue
			}
			content, err := os.ReadFile(filepath.Join(cfgPath, name))
			if err != nil {
				return nil, err
			}
			if merged, rest, ok := mergeGeneratedProfileCredentials(content, []byte(snippet)); ok {
				profileChanges = append(profileChanges, configChange{Name: name, Content: merged})
				snippet = string(rest)
			}
		}
	}
	return append([]configChange{{Name: target, Content: appendConfigSnippet(current, snippet)}}, profileChanges...), nil
}

// readConfigFileOrEmpty reads a config file; one that does not exist
// yet reads as empty, so it has the revision of empty content.
func readConfigFileOrEmpty(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// writeConfigFilesLocked validates the config with changes applied,
// replaces each changed file in order, and reloads. Nothing is
// written when validation fails, and a failed replacement restores
// the files already replaced. g.configMu must be held. Callers order
// changes so a file declaring an entity lands before a file
// referencing it.
func (g *Gateway) writeConfigFilesLocked(changes []configChange) error {
	if !configIsDir(g.cfgPath) {
		if len(changes) != 1 || changes[0].Name != filepath.Base(g.cfgPath) {
			return fmt.Errorf("single-file config: only %q can change", filepath.Base(g.cfgPath))
		}
		if err := writeSingleConfigFile(g.cfgPath, changes[0].Content); err != nil {
			return err
		}
		return g.reloadConfigFromFileLocked(g.cfgPath)
	}

	overrides := make(map[string][]byte, len(changes))
	for _, c := range changes {
		overrides[c.Name] = c.Content
	}
	if _, _, err := loadConfigOverlay(g.cfgPath, overrides); err != nil {
		return &configInvalidError{err}
	}
	if err := replaceConfigFiles(g.cfgPath, changes); err != nil {
		return err
	}
	return g.reloadConfigFromFileLocked(g.cfgPath)
}

type stagedConfigFile struct {
	name, path, tmp string
	original        []byte
	existed         bool
	mode            fs.FileMode
}

// replaceConfigFiles writes every change to a temp file first, then
// renames them into place. If a rename fails, the files already
// replaced get their original content back and files it created are
// removed, so the directory never holds a half-applied change.
func replaceConfigFiles(dir string, changes []configChange) error {
	dirSt, err := os.Stat(dir)
	if err != nil {
		return err
	}
	newFileMode := dirSt.Mode().Perm() &^ newConfigFileExecBits

	staged := make([]stagedConfigFile, 0, len(changes))
	defer func() {
		for _, s := range staged {
			_ = os.Remove(s.tmp)
		}
	}()
	for _, c := range changes {
		s := stagedConfigFile{name: c.Name, path: filepath.Join(dir, c.Name), mode: newFileMode}
		if st, err := os.Stat(s.path); err == nil {
			s.mode = st.Mode().Perm()
		}
		s.original, err = os.ReadFile(s.path)
		switch {
		case err == nil:
			s.existed = true
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("read %s: %w", c.Name, err)
		}
		if s.tmp, err = writeTempConfig(dir, c.Content); err != nil {
			return fmt.Errorf("stage %s: %w", c.Name, err)
		}
		staged = append(staged, s)
		if err := os.Chmod(s.tmp, s.mode); err != nil {
			return fmt.Errorf("stage %s: %w", c.Name, err)
		}
	}

	for i, s := range staged {
		if err := os.Rename(s.tmp, s.path); err != nil {
			err = fmt.Errorf("replace %s: %w", s.name, err)
			if rerr := restoreConfigFiles(staged[:i]); rerr != nil {
				return errors.Join(err, rerr)
			}
			return err
		}
	}
	return nil
}

func restoreConfigFiles(replaced []stagedConfigFile) error {
	var errs []error
	for _, s := range replaced {
		if !s.existed {
			if err := os.Remove(s.path); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", s.name, err))
			}
			continue
		}
		if err := writeFileAtomic(s.path, s.original, s.mode); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}

// writeSingleConfigFile validates content as the whole config, then
// replaces the file atomically, keeping its permissions.
func writeSingleConfigFile(cfgPath string, content []byte) error {
	tmpPath, err := writeTempConfig(filepath.Dir(cfgPath), content)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()
	if _, _, err := loadConfig(tmpPath); err != nil {
		return &configInvalidError{err}
	}
	if st, err := os.Stat(cfgPath); err == nil {
		_ = os.Chmod(tmpPath, st.Mode().Perm())
	}
	return os.Rename(tmpPath, cfgPath)
}

func writeFileAtomic(path string, content []byte, mode fs.FileMode) error {
	tmpPath, err := writeTempConfig(filepath.Dir(path), content)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// writeTempConfig writes content to a dotfile in dir, which the
// directory loader skips, so a half-written temp file is never loaded.
func writeTempConfig(dir string, content []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, ".clawpatrol-config-*.hcl")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// configFingerprint changes whenever a file the loader reads is added,
// removed, or modified — including an in-place edit inside a config
// directory, which leaves the directory's own mtime alone.
func configFingerprint(cfgPath string) (string, error) {
	st, err := os.Stat(cfgPath)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return fmt.Sprintf("%d:%d", st.ModTime().UnixNano(), st.Size()), nil
	}
	names, err := config.DirFileNames(cfgPath)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, name := range names {
		fst, err := os.Stat(filepath.Join(cfgPath, name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s:%d:%d;", name, fst.ModTime().UnixNano(), fst.Size())
	}
	return b.String(), nil
}
