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
// writes each changed file atomically in order, and reloads. Nothing
// is written when validation fails. g.configMu must be held. Callers
// order changes so a file declaring an entity lands before a file
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
	dirSt, err := os.Stat(g.cfgPath)
	if err != nil {
		return err
	}
	newFileMode := dirSt.Mode().Perm() &^ newConfigFileExecBits
	for _, c := range changes {
		path := filepath.Join(g.cfgPath, c.Name)
		mode := newFileMode
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
		if err := writeFileAtomic(path, c.Content, mode); err != nil {
			return fmt.Errorf("write %s: %w", c.Name, err)
		}
	}
	return g.reloadConfigFromFileLocked(g.cfgPath)
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
