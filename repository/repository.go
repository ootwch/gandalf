// Copyright 2015 gandalf authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"bytes"
	"sync"

	"github.com/tsuru/config"
	"github.com/ootwch/gandalf/db"
	"github.com/ootwch/gandalf/fs"
	"github.com/ootwch/gandalf/multipartzip"
	"github.com/tsuru/tsuru/log"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/yaml.v2"
)

var tempDir string

var (
	ErrRepositoryAlreadyExists = errors.New("repository already exists")
	ErrRepositoryNotFound      = errors.New("repository not found")
)

func tempDirLocation() string {
	if tempDir == "" {
		tempDir, _ = config.GetString("repository:tempDir")
	}
	return tempDir
}

// Repository represents a Git repository. A Git repository is a record in the
// database and a directory in the filesystem (the bare repository).
type Repository struct {
	Name          string `bson:"_id"`
	Users         []string
	ReadOnlyUsers []string
	IsPublic      bool
}

type Links struct {
	TarArchive string `json:"tarArchive"`
	ZipArchive string `json:"zipArchive"`
}

type GitUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

func (gu GitUser) String() string {
	return fmt.Sprintf("%s <%s>", gu.Name, gu.Email)
}

type GitCommit struct {
	Message   string
	Author    GitUser
	Committer GitUser
	Branch    string
}

type Ref struct {
	Ref       string   `json:"ref"`
	Name      string   `json:"name"`
	Author    *GitUser `json:"author"`
	Committer *GitUser `json:"committer"`
	Tagger    *GitUser `json:"tagger"`
	Links     *Links   `json:"_links"`
	Subject   string   `json:"subject"`
	CreatedAt string   `json:"createdAt"`
}

type GitLog struct {
	Ref       string   `json:"ref"`
	Author    *GitUser `json:"author"`
	Committer *GitUser `json:"committer"`
	Subject   string   `json:"subject"`
	CreatedAt string   `json:"createdAt"`
	Parent    []string `json:"parent"`
}

type GitHistory struct {
	Commits []GitLog `json:"commits"`
	Next    string   `json:"next"`
}

// exists returns whether the given file or directory exists or not
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// MarshalJSON marshals the Repository in json format.
func (r *Repository) MarshalJSON() ([]byte, error) {
	data := map[string]interface{}{
		"name":    r.Name,
		"public":  r.IsPublic,
		"ssh_url": r.ReadWriteURL(),
		"git_url": r.ReadOnlyURL(),
	}
	return json.Marshal(&data)
}

// New creates a representation of a git repository. It creates a Git
// repository using the "bare-dir" setting and saves repository's meta data in
// the database.
func New(name string, users, readOnlyUsers []string, isPublic bool) (*Repository, error) {
	log.Debugf("Creating repository %q", name)
	r := &Repository{Name: name, Users: users, ReadOnlyUsers: readOnlyUsers, IsPublic: isPublic}
	if v, err := r.isValid(); !v {
		log.Errorf("repository.New: Invalid repository %q: %s", name, err)
		return r, err
	}
	conn, err := db.Conn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	err = conn.Repository().Insert(r)
	if err != nil {
		if mgo.IsDup(err) {
			return nil, ErrRepositoryAlreadyExists
		}
		return nil, err
	}
	if err := newBare(name); err != nil {
		log.Errorf("repository.New: Error creating bare repository for %q: %s", name, err)
		conn.Repository().Remove(bson.M{"_id": r.Name})
		return r, err
	}
	barePath := barePath(name)
	if barePath != "" && isPublic {
		if f, createErr := fs.Filesystem().Create(barePath + "/git-daemon-export-ok"); createErr == nil {
			f.Close()
		}
	}
	return r, err
}

// Get find a repository by name.
func Get(name string) (Repository, error) {
	var r Repository
	conn, err := db.Conn()
	if err != nil {
		return r, err
	}
	defer conn.Close()
	err = conn.Repository().FindId(name).One(&r)
	if err == mgo.ErrNotFound {
		return r, ErrRepositoryNotFound
	}
	return r, err
}

// Remove deletes the repository from the database and removes it's bare Git
// repository.
func Remove(name string) error {
	log.Debugf("Removing repository %q", name)
	if err := removeBare(name); err != nil {
		log.Errorf("repository.Remove: Error removing bare repository %q: %s", name, err)
	}
	conn, err := db.Conn()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Repository().RemoveId(name); err != nil {
		if err == mgo.ErrNotFound {
			return ErrRepositoryNotFound
		}
		return err
	}
	return nil
}

// Update update a repository data.
func Update(name string, newData Repository) error {
	log.Debugf("Updating repository %q data", name)
	repo, err := Get(name)
	if err != nil {
		log.Errorf("repository.Update(%q): %s", name, err)
		return err
	}
	conn, err := db.Conn()
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(newData.Name) > 0 && newData.Name != repo.Name {
		oldName := repo.Name
		log.Debugf("Renaming repository %q to %q", oldName, newData.Name)
		err = conn.Repository().Insert(newData)
		if err != nil {
			log.Errorf("repository.Rename: Error adding new repository %q: %s", newData.Name, err)
			return err
		}
		err = conn.Repository().RemoveId(oldName)
		if err != nil {
			log.Errorf("repository.Rename: Error removing old repository %q: %s", oldName, err)
			return err
		}
		err = fs.Filesystem().Rename(barePath(oldName), barePath(newData.Name))
		if err != nil {
			log.Errorf("repository.Rename: Error renaming old repository in filesystem %q: %s", oldName, err)
			return err
		}
	} else {
		err = conn.Repository().UpdateId(repo.Name, newData)
		if err != nil {
			log.Errorf("repository.Update: Error updating repository data %q: %s", repo.Name, err)
			return err
		}
	}
	return nil
}

// ReadWriteURL formats the git ssh url and return it. If no remote is configured in
// gandalf.conf, this method panics.
func (r *Repository) ReadWriteURL() string {
	uid, err := config.GetString("uid")
	if err != nil {
		panic(err.Error())
	}
	remote := uid + "@%s:%s.git"
	if useSSH, _ := config.GetBool("git:ssh:use"); useSSH {
		var port string
		port, err = config.GetString("git:ssh:port")
		if err == nil {
			remote = "ssh://" + uid + "@%s:" + port + "/%s.git"
		} else {
			remote = "ssh://" + uid + "@%s/%s.git"
		}
	}
	host, err := config.GetString("host")
	if err != nil {
		panic(err.Error())
	}
	return fmt.Sprintf(remote, host, r.Name)
}

// ReadOnly formats the git url and return it. If no host is configured in
// gandalf.conf, this method panics.
func (r *Repository) ReadOnlyURL() string {
	remote := "git://%s/%s.git"
	if useSSH, _ := config.GetBool("git:ssh:use"); useSSH {
		uid, err := config.GetString("uid")
		if err != nil {
			panic(err.Error())
		}
		port, err := config.GetString("git:ssh:port")
		if err == nil {
			remote = "ssh://" + uid + "@%s:" + port + "/%s.git"
		} else {
			remote = "ssh://" + uid + "@%s/%s.git"
		}
	}
	host, err := config.GetString("readonly-host")
	if err != nil {
		host, err = config.GetString("host")
		if err != nil {
			panic(err)
		}
	}
	return fmt.Sprintf(remote, host, r.Name)
}

// Validates a repository
// A valid repository MUST have:
//  - a name without any special chars only alphanumeric and underlines are allowed.
//  - at least one user in users array
// A valid repository MAY have one namespace since the following is obeyed:
//  - a namespace is optional
//  - a namespace contains only alphanumerics, underlines, @´s, -´s, +´s and
//    periods but it does not start with a period (.)
//  - one and exactly one slash (/) separates namespace and the actual name
func (r *Repository) isValid() (bool, error) {
	// The following regex validates the name of a repository, which may
	// contain a namespace. If a namespace is used, we validate it
	// accordingly (see comments above)
	m, e := regexp.Match(`^([\w-+@][\w-+.@]*/)?[\w-]+$`, []byte(r.Name))
	if e != nil {
		panic(e)
	}
	if !m {
		return false, &InvalidRepositoryError{message: "repository name is not valid"}
	}
	absPath, err := filepath.Abs(barePath(r.Name))
	if err != nil || !strings.HasPrefix(absPath, bare) {
		return false, &InvalidRepositoryError{message: "repository name is not valid"}
	}
	if len(r.Users) == 0 {
		return false, &InvalidRepositoryError{message: "repository should have at least one user"}
	}
	return true, nil
}

// GrantAccess gives full or read-only permission for users in all specified repositories.
// If any of the repositories/users does not exist, GrantAccess just skips it.
func GrantAccess(rNames, uNames []string, readOnly bool) error {
	conn, err := db.Conn()
	if err != nil {
		return err
	}
	defer conn.Close()
	var info *mgo.ChangeInfo
	if readOnly {
		info, err = conn.Repository().UpdateAll(bson.M{"_id": bson.M{"$in": rNames}}, bson.M{"$addToSet": bson.M{"readonlyusers": bson.M{"$each": uNames}}})
	} else {
		info, err = conn.Repository().UpdateAll(bson.M{"_id": bson.M{"$in": rNames}}, bson.M{"$addToSet": bson.M{"users": bson.M{"$each": uNames}}})
	}
	if err != nil {
		return err
	}
	if info.Updated < 1 {
		return ErrRepositoryNotFound
	}
	return nil
}

// RevokeAccess revokes write permission from users in all specified
// repositories.
func RevokeAccess(rNames, uNames []string, readOnly bool) error {
	conn, err := db.Conn()
	if err != nil {
		return err
	}
	defer conn.Close()
	var info *mgo.ChangeInfo
	if readOnly {
		info, err = conn.Repository().UpdateAll(bson.M{"_id": bson.M{"$in": rNames}}, bson.M{"$pullAll": bson.M{"readonlyusers": uNames}})
	} else {
		info, err = conn.Repository().UpdateAll(bson.M{"_id": bson.M{"$in": rNames}}, bson.M{"$pullAll": bson.M{"users": uNames}})
	}
	if err != nil {
		return err
	}
	if info.Updated < 1 {
		return ErrRepositoryNotFound
	}
	return nil
}

func GetArchiveUrl(repo, ref, format string) string {
	url := "/repository/%s/archive?ref=%s&format=%s"
	return fmt.Sprintf(url, repo, ref, format)
}

type ArchiveFormat int

const (
	Zip ArchiveFormat = iota
	Tar
	TarGz
)

type ContentRetriever interface {
	GetContents(repo, ref, path string) ([]byte, error)
	SetContents(repo, path string, content []byte, commit GitCommit) (string, error)
	DeleteFile(repo, path string, commit GitCommit) (string, error)

	GetArchive(repo, ref string, format ArchiveFormat) ([]byte, error)
	GetTree(repo, ref, path, mode string) ([]map[string]string, error)
	GetForEachRef(repo, pattern string) ([]Ref, error)
	GetBranches(repo string) ([]Ref, error)
	GetDiff(repo, lastCommit, previousCommit string) ([]byte, error)
	GetTags(repo string) ([]Ref, error)
	TempClone(repo string) (string, func(), error)
	Checkout(cloneDir, branch string, isNew bool) error
	AddAll(cloneDir string) error
	Commit(cloneDir, message string, author, committer GitUser) error
	Push(cloneDir, branch string) error
	CommitZip(repo string, z *multipart.FileHeader, c GitCommit) (*Ref, error)
	GetLogs(repo, hash string, total int, path string) (*GitHistory, error)

	// Vitruvius specific tree
	GetTreeVitruvius(repo, ref, path, mode string, typefiles []string) ([]Leaf, error)

}

var Retriever ContentRetriever

type GitContentRetriever struct{}

func (*GitContentRetriever) GetContents(repo, ref, path string) ([]byte, error) {
	log.Debugf("Reading file %q", path)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error running git (%s) (%s).", err, err.(*exec.ExitError).Stderr)
	}
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain file %s on ref %s of repository %s (Repository does not exist).", path, ref, repo)
	}
	cmd := exec.Command(gitPath, "show", fmt.Sprintf("%s:%s", ref, path))
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain file %s on ref %s of repository %s (%s) (%s).", path, ref, repo, err, err.(*exec.ExitError).Stderr,)
	}
	return out, nil
}

func (*GitContentRetriever) GetArchive(repo, ref string, format ArchiveFormat) ([]byte, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain archive for ref %s of repository %s (%s).", ref, repo, err)
	}
	var archiveFormat string
	switch format {
	case Tar:
		archiveFormat = "--format=tar"
	case TarGz:
		archiveFormat = "--format=tar.gz"
	default:
		archiveFormat = "--format=zip"
	}
	prefix := fmt.Sprintf("--prefix=%s-%s/", repo, ref)
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain archive for ref %s of repository %s (Repository does not exist).", ref, repo)
	}
	cmd := exec.Command(gitPath, "archive", ref, prefix, archiveFormat)
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain archive for ref %s of repository %s (%s).", ref, repo, err)
	}
	return out, nil
}

func (*GitContentRetriever) GetTree(repo, ref, path, mode string) ([]map[string]string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error when trying to find tree %s on ref %s of repository %s (%s).", path, ref, repo, err)
	}
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain tree %s on ref %s of repository %s (Repository does not exist).", path, ref, repo)
	}
	var tree_parameter string
	if strings.Contains(mode, "tree") {
		tree_parameter = "-rt" // also show tree objects
	} else {
		tree_parameter = "-r" // default
	}

	cmd := exec.Command(gitPath, "ls-tree", tree_parameter, ref, path) // also show tree objects

	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Error when trying to execute ls-tree %s in %s on ref %s of repository %s (%s). '%s'", path, cmd.Dir, ref, repo, err, err.Error())
	}
	log.Debugf("git tree_parameter: %s ref: %s path: %s", tree_parameter, ref, path)
	lines := strings.Split(string(out), "\n")
	objectCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		objectCount++
	}
	objects := make([]map[string]string, objectCount)
	objectCount = 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tabbed := strings.Split(line, "\t")
		meta, filepath := tabbed[0], tabbed[1]
		meta_parts := strings.Split(meta, " ")
		permission, filetype, hash := meta_parts[0], meta_parts[1], meta_parts[2]
		object := make(map[string]string)
		object["permission"] = permission
		object["filetype"] = filetype
		object["hash"] = hash
		object["path"] = strings.TrimSpace(strings.Trim(filepath, "\""))
		object["rawPath"] = filepath
		objects[objectCount] = object
		objectCount++
	}
	return objects, nil
}

func (*GitContentRetriever) GetForEachRef(repo, pattern string) ([]Ref, error) {
	var ref, name, committerName, committerEmail, committerDate, authorName, authorEmail, authorDate, taggerName, taggerEmail, taggerDate, subject string
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain the refs of repository %s (%s).", repo, err)
	}
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain the refs of repository %s (Repository does not exist).", repo)
	}
	format := "%(objectname)%09%(refname:short)%09%(committername)%09%(committeremail)%09%(committerdate)%09%(authorname)%09%(authoremail)%09%(authordate)%09%(taggername)%09%(taggeremail)%09%(taggerdate)%09%(contents:subject)"
	cmd := exec.Command(gitPath, "for-each-ref", "--sort=-committerdate", "--format", format)
	if len(pattern) > 0 {
		cmd.Args = append(cmd.Args, pattern)
	}
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain the refs of repository %s (%s).", repo, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	objectCount := len(lines)
	if len(lines) == 1 && len(lines[0]) == 0 {
		objectCount = 0
	}
	objects := make([]Ref, objectCount)
	objectCount = 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) > 10 { // let there be commits with empty subject
			ref = fields[0]
			name = fields[1]
			committerName = fields[2]
			committerEmail = fields[3]
			committerDate = fields[4]
			authorName = fields[5]
			authorEmail = fields[6]
			authorDate = fields[7]
			taggerName = fields[8]
			taggerEmail = fields[9]
			taggerDate = fields[10]
			subject = strings.Join(fields[11:], "\t") // let there be subjects with \t
		} else {
			log.Errorf("Could not match required ref elements for %s (invalid git input: %s).", repo, line)
			continue
		}
		object := Ref{}
		object.Ref = ref
		object.Name = name
		object.Subject = subject
		if taggerDate != "" {
			object.CreatedAt = taggerDate
		} else {
			object.CreatedAt = authorDate
		}
		object.Committer = &GitUser{
			Name:  committerName,
			Email: committerEmail,
			Date:  committerDate,
		}
		object.Author = &GitUser{
			Name:  authorName,
			Email: authorEmail,
			Date:  authorDate,
		}
		object.Tagger = &GitUser{
			Name:  taggerName,
			Email: taggerEmail,
			Date:  taggerDate,
		}
		object.Links = &Links{
			ZipArchive: GetArchiveUrl(repo, name, "zip"),
			TarArchive: GetArchiveUrl(repo, name, "tar.gz"),
		}
		objects[objectCount] = object
		objectCount++
	}
	return objects[0:objectCount], nil
}

func (*GitContentRetriever) GetBranches(repo string) ([]Ref, error) {
	branches, err := retriever().GetForEachRef(repo, "refs/heads/")
	return branches, err
}

func (*GitContentRetriever) GetDiff(repo, previousCommit, lastCommit string) ([]byte, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain diff with commits %s and %s of repository %s (%s).", lastCommit, previousCommit, repo, err)
	}
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain diff with commits %s and %s of repository %s (Repository does not exist).", lastCommit, previousCommit, repo)
	}
	cmd := exec.Command(gitPath, "diff", previousCommit, lastCommit)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain diff with commits %s and %s of repository %s (%s).", lastCommit, previousCommit, repo, err)
	}
	return out, nil
}

func (*GitContentRetriever) GetTags(repo string) ([]Ref, error) {
	return retriever().GetForEachRef(repo, "refs/tags/")
}

func (*GitContentRetriever) TempClone(repo string) (cloneDir string, cleanUp func(), err error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", nil, fmt.Errorf("Error when trying to clone repository %s (%s).", repo, err)
	}
	repoDir := barePath(repo)
	repoExists, err := exists(repoDir)
	if err != nil || !repoExists {
		return "", nil, fmt.Errorf("Error when trying to clone repository %s (Repository does not exist).", repo)
	}
	cloneDir, err = ioutil.TempDir(tempDir, "gandalf_clone")
	if err != nil {
		return "", nil, fmt.Errorf("Error when trying to clone repository %s (Could not create temporary directory).", repo)
	}
	cleanUp = func() {
		os.RemoveAll(cloneDir)
	}
	cmd := exec.Command(gitPath, "clone", repoDir, cloneDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return cloneDir, cleanUp, fmt.Errorf("Error when trying to clone repository %s into %s (%s [%s]).", repo, cloneDir, err, out)
	}
	return cloneDir, cleanUp, nil
}

func (*GitContentRetriever) Checkout(cloneDir, branch string, isNew bool) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("Error when trying to checkout clone %s into branch %s (%s).", cloneDir, branch, err)
	}
	cloneExists, err := exists(cloneDir)
	if err != nil || !cloneExists {
		return fmt.Errorf("Error when trying to checkout clone %s into branch %s (Clone does not exist).", cloneDir, branch)
	}
	cmd := exec.Command(gitPath, "checkout")
	if isNew {
		cmd.Args = append(cmd.Args, "-b")
	}
	cmd.Args = append(cmd.Args, branch)
	cmd.Dir = cloneDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error when trying to checkout clone %s into branch %s (%s [%s]).", cloneDir, branch, err, out)
	}
	return nil
}

func (*GitContentRetriever) AddAll(cloneDir string) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("Error when trying to add all to clone %s (%s).", cloneDir, err)
	}
	cloneExists, err := exists(cloneDir)
	if err != nil || !cloneExists {
		return fmt.Errorf("Error when trying to add all to clone %s (Clone does not exist).", cloneDir)
	}
	cmd := exec.Command(gitPath, "add", "--all")
	cmd.Dir = cloneDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error when trying to add all to clone %s (%s [%s]).", cloneDir, err, out)
	}
	return nil
}

func (*GitContentRetriever) Commit(cloneDir, message string, author, committer GitUser) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("Error when trying to commit to clone %s (%s).", cloneDir, err)
	}
	cloneExists, err := exists(cloneDir)
	if err != nil || !cloneExists {
		return fmt.Errorf("Error when trying to commit to clone %s (Clone does not exist).", cloneDir)
	}
	cmd := exec.Command(gitPath, "commit", "-m", message, "--author", author.String(), "--allow-empty-message")
	env := os.Environ()
	env = append(env, fmt.Sprintf("GIT_COMMITTER_NAME=%s", committer.Name))
	env = append(env, fmt.Sprintf("GIT_COMMITTER_EMAIL=%s", committer.Email))
	cmd.Env = env
	cmd.Dir = cloneDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error when trying to commit to clone %s (%s [%s]).", cloneDir, err, out)
	}
	return nil
}

func (*GitContentRetriever) DeleteFile(repo, path string, commit GitCommit) (string, error) {

	logstring := "File to be deleted: " + "path" + "\n"
	log.Debugf("Delete File %q", path)

	gitPath, err := exec.LookPath("git")
	repo_path := barePath(repo)

	var tree_hash string

	// git read-tree #branch  Need to ensure we have the correct tree?
	cmd_read_tree := exec.Command(gitPath, "read-tree", commit.Branch)
	cmd_read_tree.Dir = repo_path

	// remove file from staging area (index)
	cmd_delete := exec.Command(gitPath, "rm", "--cached", "-r", path)
	cmd_delete.Dir = repo_path

	// git write-tree create/updates the tree (directory) entries => TREE_SHA
	cmd_write_tree := exec.Command(gitPath, "write-tree")
	cmd_write_tree.Dir = repo_path

	// If the requested branch does not exist, create it.
	cmd_check_branch := exec.Command(gitPath, "rev-parse", "--verify", commit.Branch)
	cmd_check_branch.Dir = repo_path

	// Protected by mutex
		var staging_mutex = &sync.Mutex{}


		/* The next part has to be atomic, due to git only having one index/staging area */

		staging_mutex.Lock()
		defer staging_mutex.Unlock() //ensure unlocking

		current_revision_byte, err := cmd_check_branch.Output()
		current_revision := strings.TrimSpace(string(current_revision_byte))
		logstring += fmt.Sprintf("Current revision for branch %s: %s\n", commit.Branch, current_revision)

		// If branch does not exist, error.
		if current_revision == "" {
			return "", fmt.Errorf("Error deleting file. Branch does not exist (%s)\n%s", err, logstring)
		} else {
			// Read tree for given branch
			_, err = cmd_read_tree.Output()
			if err != nil {
				return "", fmt.Errorf("Error reading tree for branch %s (%s)\n%s", commit.Branch, err, logstring)
			}
		}

		_, err = cmd_delete.Output()
		if err != nil {
			return "", fmt.Errorf("Error deleting file from index for branch %s (%s) (%s)\n%s", commit.Branch, err, err.(*exec.ExitError).Stderr, logstring)
		}

		// git write-tree create/updates the tree (directory) entries => TREE_SHA

		tree_hash_byte, err := cmd_write_tree.Output()
		tree_hash = strings.TrimSpace(string(tree_hash_byte))

		logstring += fmt.Sprintf("TREEHASH: <%s>\n", tree_hash)

		if err != nil {
			return "", fmt.Errorf("Delete file error: Error writing tree for branch %s (%s)\n%s", commit.Branch, err, logstring)
		}
		// staging_mutex.Unlock() // free the staging area - it is not needed for the remaining steps
	// End mutex

	// TODO: deferring the unlock does not really work... have to fix UNLOCK of UNLOCKED mutex is not good

	// git commit-tree #TREE_SHA -m "Second Commit to root?" -p #PARENT_SHA
	var cmd_commit *exec.Cmd
	if current_revision == "" { // TODO: Not reachable
		cmd_commit = exec.Command(gitPath, "commit-tree", tree_hash, "-m", fmt.Sprintf(`"%s"`, commit.Message))
	} else {
		cmd_commit = exec.Command(gitPath, "commit-tree", tree_hash, "-m", fmt.Sprintf(`"%s"`, commit.Message), "-p", current_revision)
	}


	cmd_commit.Dir = repo_path

	env := os.Environ()
	env = append(env, fmt.Sprintf("GIT_COMMITTER_NAME=%s", commit.Committer.Name))
	env = append(env, fmt.Sprintf("GIT_COMMITTER_EMAIL=%s", commit.Committer.Email))
	env = append(env, fmt.Sprintf("GIT_AUTHOR_NAME=%s", commit.Committer.Name))
	env = append(env, fmt.Sprintf("GIT_AUTHOR_EMAIL=%s", commit.Committer.Email))
	cmd_commit.Env = env

	commit_hash_byte, err := cmd_commit.Output()
	commit_hash := strings.TrimSpace(string(commit_hash_byte))

	logstring += fmt.Sprintf("Commit hash: %s", commit_hash)

	if err != nil {
		return "", fmt.Errorf("Error committing to branch %s (%s) (%s)\n%s", commit.Branch, err, err.(*exec.ExitError).Stderr, logstring)
	}




	// Set #branch to newest commit (create branch if needed)
	// git update-ref refs/heads/master <newvalue> <oldvalue>
	// the git command verifies that the branch is only created if it does not exist - perhaps useless double-checking?
	var cmd_update_ref *exec.Cmd
	if current_revision == "" {
		cmd_update_ref = exec.Command(gitPath, "update-ref", fmt.Sprintf("refs/heads/%s", commit.Branch), commit_hash, "")
	} else {
		cmd_update_ref = exec.Command(gitPath, "update-ref", fmt.Sprintf("refs/heads/%s", commit.Branch), commit_hash, current_revision)
	}

	cmd_update_ref.Dir = repo_path

	_, err = cmd_update_ref.Output()

	if err != nil {
		return "", fmt.Errorf("Error creating/updating branch %s (%s)\n(%s)\n%s", commit.Branch, err, err.(*exec.ExitError).Stderr, logstring)
	}

	//return "", fmt.Errorf("Error creating/updating branch %s (%s)\n(%s)\n%s", commit.Branch, err, "", logstring)

	return commit_hash, nil


}


func (*GitContentRetriever) SetContents(repo, path string, content []byte, commit GitCommit) (string, error) {
	// git hash --stdin -w creates the file object => FILE_SHA
	// ==> LOCK
	// git read-tree #branch  Need to ensure we have the correct tree?
	// git update-index --add --cacheinfo 100644 #FILE_SHA path/file.txt registers it
	// git write-tree create/updates the tree (directory) entries => TREE_SHA
	// ==> RELEASE LOCK
	// git commit-tree #TREE_SHA -m "Second Commit to root?" -p #PARENT_SHA
	// Set #branch to newest commit

	gitPath, err := exec.LookPath("git")
	repo_path := barePath(repo)


	logstring := gitPath + " " + repo_path + " " + string(content) + "\n"
	logstring += "Starting SetContents\n"

    log.Debugf("Create/Update file %q", gitPath)


	cmdOutput := &bytes.Buffer{}
	cmdError := &bytes.Buffer{}

	cmd_hash := exec.Command( gitPath, "hash-object", "--stdin", "-w")
	cmd_hash.Dir = repo_path
	cmd_hash.Stdout = cmdOutput
	cmd_hash.Stderr = cmdError
	cmdInPipe, err := cmd_hash.StdinPipe()

	if err != nil {
		logstring += fmt.Sprintf("PIPE<ERR: %s", err)
	}

	err = cmd_hash.Start()

	if err != nil {
		logstring += fmt.Sprintf("STARTERR: %s", err)
	}

	// Send content to pipe (git hash-object) and close pipe
	cmdInPipe.Write([]byte(content))
	cmdInPipe.Close()
	err = cmd_hash.Wait()

	if err != nil {
		logstring += fmt.Sprintf("WAITERR: %s", err)
	}

	logstring += fmt.Sprintf("OUTPUT: %s\n", string(cmdOutput.Bytes()))
	logstring += fmt.Sprintf("STDERR: %s\n", string(cmdError.Bytes()))

	if err != nil {
		return "", fmt.Errorf("Error storing file to repository:  %s\n%s", err, logstring)
	}

	object_hash := string(cmdOutput.Bytes())

	var tree_hash string

	// git read-tree #branch  Need to ensure we have the correct tree?
	cmd_read_tree := exec.Command(gitPath, "read-tree", commit.Branch)
	cmd_read_tree.Dir = repo_path

	// git clear-tree   Need to ensure we have an empty tree
	cmd_clear_tree := exec.Command(gitPath, "read-tree", "--empty")
	cmd_clear_tree.Dir = repo_path

	// git update-index --add --cacheinfo 100644 #FILE_SHA path/file.txt registers it
	cmd_update_index := exec.Command(gitPath, "update-index", "--add", "--cacheinfo", "100644", object_hash, path)
	cmd_update_index.Dir = repo_path

	// git write-tree create/updates the tree (directory) entries => TREE_SHA
	cmd_write_tree := exec.Command(gitPath, "write-tree")
	cmd_write_tree.Dir = repo_path

	// If the requested branch does not exist, create it.
	cmd_check_branch := exec.Command(gitPath, "rev-parse", "--verify", commit.Branch)
	cmd_check_branch.Dir = repo_path

	// Protected by mutex
		var staging_mutex = &sync.Mutex{}


		/* The next part has to be atomic, due to git only having one index/staging area */

		staging_mutex.Lock()
		defer staging_mutex.Unlock() //ensure unlocking

		current_revision_byte, err := cmd_check_branch.Output()
		current_revision := strings.TrimSpace(string(current_revision_byte))
		logstring += fmt.Sprintf("Current revision for branch %s: %s\n", commit.Branch, current_revision)

		// If branch does not exist, create first entry in empty tree
		// TODO: Is that really what is needed? Only for master?
		if current_revision == "" {
			logstring += "No revision - Clearing Tree\n"
			_,err = cmd_clear_tree.Output()
			if err != nil {
				return "", fmt.Errorf("Error clearing tree (%s)\n%s", err, logstring)
			}
		} else {
			// Read tree for given branch
			_, err = cmd_read_tree.Output()
			if err != nil {
				return "", fmt.Errorf("Error reading tree for branch %s (%s)\n%s", commit.Branch, err, logstring)
			}
		}

		_, err = cmd_update_index.Output()
		if err != nil {
			return "", fmt.Errorf("Error updating index for branch %s (%s) (%s)\n%s", commit.Branch, err, err.(*exec.ExitError).Stderr, logstring)
		}

		// git write-tree create/updates the tree (directory) entries => TREE_SHA

		tree_hash_byte, err := cmd_write_tree.Output()
		tree_hash = strings.TrimSpace(string(tree_hash_byte))

		logstring += fmt.Sprintf("TREEHASH: <%s>\n", tree_hash)

		if err != nil {
			return "", fmt.Errorf("Error writing tree for branch %s (%s)\n%s", commit.Branch, err, logstring)
		}
		// staging_mutex.Unlock() // free the staging area - it is not needed for the remaining steps
	// End mutex

	// TODO: deferring the unlock does not really work... have to fix UNLOCK of UNLOCKED mutex is not good

	// git commit-tree #TREE_SHA -m "Second Commit to root?" -p #PARENT_SHA
	var cmd_commit *exec.Cmd
	if current_revision == "" {
		cmd_commit = exec.Command(gitPath, "commit-tree", tree_hash, "-m", fmt.Sprintf(`"%s"`, commit.Message))
	} else {
		cmd_commit = exec.Command(gitPath, "commit-tree", tree_hash, "-m", fmt.Sprintf(`"%s"`, commit.Message), "-p", current_revision)
	}


	cmd_commit.Dir = repo_path

	env := os.Environ()
	env = append(env, fmt.Sprintf("GIT_COMMITTER_NAME=%s", commit.Committer.Name))
	env = append(env, fmt.Sprintf("GIT_COMMITTER_EMAIL=%s", commit.Committer.Email))
	env = append(env, fmt.Sprintf("GIT_AUTHOR_NAME=%s", commit.Committer.Name))
	env = append(env, fmt.Sprintf("GIT_AUTHOR_EMAIL=%s", commit.Committer.Email))
	cmd_commit.Env = env

	commit_hash_byte, err := cmd_commit.Output()
	commit_hash := strings.TrimSpace(string(commit_hash_byte))

	logstring += fmt.Sprintf("Commit hash: %s", commit_hash)

	if err != nil {
		return "", fmt.Errorf("Error committing to branch %s (%s) (%s)\n%s", commit.Branch, err, err.(*exec.ExitError).Stderr, logstring)
	}




	// Set #branch to newest commit (create branch if needed)
	// git update-ref refs/heads/master <newvalue> <oldvalue>
	// the git command verifies that the branch is only created if it does not exist - perhaps useless double-checking?
	var cmd_update_ref *exec.Cmd
	if current_revision == "" {
		cmd_update_ref = exec.Command(gitPath, "update-ref", fmt.Sprintf("refs/heads/%s", commit.Branch), commit_hash, "")
	} else {
		cmd_update_ref = exec.Command(gitPath, "update-ref", fmt.Sprintf("refs/heads/%s", commit.Branch), commit_hash, current_revision)
	}

	cmd_update_ref.Dir = repo_path

	_, err = cmd_update_ref.Output()

	if err != nil {
		return "", fmt.Errorf("Error creating/updating branch %s (%s)\n(%s)\n%s", commit.Branch, err, err.(*exec.ExitError).Stderr, logstring)
	}

	//return "", fmt.Errorf("Error creating/updating branch %s (%s)\n(%s)\n%s", commit.Branch, err, "", logstring)

	return commit_hash, nil
	//return nil, fmt.Errorf(logstring+"Succeeded?")  //TODO: return ref!
}

func (*GitContentRetriever) Push(cloneDir, branch string) error {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("Error when trying to push clone %s (%s).", cloneDir, err)
	}
	cloneExists, err := exists(cloneDir)
	if err != nil || !cloneExists {
		return fmt.Errorf("Error when trying to push clone %s into origin's %s branch (Clone does not exist).", cloneDir, branch)
	}
	cmd := exec.Command(gitPath, "push", "origin", branch)
	cmd.Dir = cloneDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error when trying to push clone %s into origin's %s branch (%s [%s]).", cloneDir, branch, err, out)
	}
	return nil
}

func (*GitContentRetriever) CommitZip(repo string, z *multipart.FileHeader, c GitCommit) (*Ref, error) {
	cloneDir, cleanUp, err := TempClone(repo)
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not clone: %s", repo, err)
	}
	err = Checkout(cloneDir, c.Branch, false)
	if err != nil {
		err = Checkout(cloneDir, c.Branch, true)
		if err != nil {
			return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not checkout: %s", repo, err)
		}
	}
	err = multipartzip.ExtractZip(z, cloneDir)
	if err != nil {
		return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not extract: %s", repo, err)
	}
	err = AddAll(cloneDir)
	if err != nil {
		return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not add all: %s", repo, err)
	}
	err = Commit(cloneDir, c.Message, c.Author, c.Committer)
	if err != nil {
		return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not commit: %s", repo, err)
	}
	err = Push(cloneDir, c.Branch)
	if err != nil {
		return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not push: %s", repo, err)
	}
	branches, err := GetBranches(repo)
	if err != nil {
		return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not get branches: %s", repo, err)
	}
	for _, branch := range branches {
		if branch.Name == c.Branch {
			return &branch, nil
		}
	}
	return nil, fmt.Errorf("Error when trying to commit zip to repository %s, could not check branch: %s", repo, err)
}

func (*GitContentRetriever) GetLogs(repo, hash string, total int, path string) (*GitHistory, error) {
	if hash == "" {
		hash = "master"
	}
	if total < 1 {
		total = 1
	}
	totalPagination := total + 1
	var last string
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain the log of repository %s (%s).", repo, err)
	}
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain the log of repository %s (Repository does not exist).", repo)
	}
	format := "%H%x09%an%x09%ae%x09%ad%x09%cn%x09%ce%x09%cd%x09%P%x09%s"
	cmd := exec.Command(gitPath, "--no-pager", "log", fmt.Sprintf("-n %d", totalPagination), fmt.Sprintf("--format=%s", format), hash, "--", path)
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Error when trying to obtain the log of repository %s (%s).", repo, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	objectCount := len(lines)
	if len(lines) == 1 && len(lines[0]) == 0 {
		objectCount = 0
	}
	if objectCount > total {
		last = lines[objectCount-1]
		lines = lines[0 : objectCount-1]
		objectCount -= 1
	}
	history := GitHistory{}
	commits := make([]GitLog, objectCount)
	objectCount = 0
	for _, line := range lines {
		var parent, subject string
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 { // let there be commits with empty subject and no parents
			return nil, fmt.Errorf("Error when trying to obtain the log of repository %s (Invalid git log output [%s]).", repo, out)
		}
		if len(fields) > 8 {
			parent = fields[7]
			subject = strings.Join(fields[8:], "\t") // let there be subjects with \t
		}
		commit := GitLog{}
		commit.Ref = fields[0]
		commit.Subject = subject
		commit.CreatedAt = fields[3]
		commit.Committer = &GitUser{
			Name:  fields[4],
			Email: fields[5],
			Date:  fields[6],
		}
		commit.Author = &GitUser{
			Name:  fields[1],
			Email: fields[2],
			Date:  fields[3],
		}
		if len(parent) > 0 {
			parents := strings.Split(parent, " ")
			parentCount := len(parents)
			aux := make([]string, parentCount)
			parentCount = 0
			for _, item := range parents {
				aux[parentCount] = item
				parentCount++
			}
			commit.Parent = aux
		}
		commits[objectCount] = commit
		objectCount++
	}
	history.Commits = commits
	if last != "" {
		fields := strings.Split(last, "\t")
		history.Next = fields[0]
	} else {
		history.Next = ""
	}
	return &history, nil
}


// Vitruvius-specific tree

// Leaf element
// The tags define the keys used in JSON
type Leaf struct {
	Permission string `json:"permission"`
	Filetype string `json:"filetype"`
	Hash string `json:"hash"`
	Path string `json:"path"`
	RawPath string `json:"rawPath"`
	Object_identifier string `json:"object_identifier"`
	Object_type string `json:"object_type"`
	Object_name string `json:"object_name"`
	Object_description string `json:"object_description"`
	Object_configfile string `json:"object_configfile"`
	Children []Leaf `json:"children"`

}


// Returns {Path, Name, isDir=False, GUID, Name, Description} or {Path, Name, isDir=True, [...]}
func (*GitContentRetriever) GetTreeVitruvius(repo, ref, path, mode string, typefiles []string) ([]Leaf, error) {

	var err	error
	var objects []Leaf
	log.Debugf("Getting Vit-Tree %q", path)
	objects, err = treebuilder(repo, ref, path, typefiles)
	return objects, err
}

func treebuilder(repo, ref, path string, typefiles []string) ([]Leaf, error) {

	type T map[string]string

	var inner_dir []Leaf
	yaml_object := map[string]interface{}{}

	objects, err := listdir(repo, ref, path)

	if err != nil {
		return nil, err
	}

	for lineno, line := range objects {
		if line.Filetype=="tree" {
			// log.Debugf("%q is a tree object", line.Path)
//			inner_dir, err = treebuilder(repo, ref, path + "/" + line.Path + "/", typefiles)
			inner_dir, err = treebuilder(repo, ref, line.Path + "/", typefiles)

			if err != nil {
				return nil, err
			}
			if len(inner_dir)>0 {
				// log.Debugf("%q is a tree object with children", line.Path)
				objects[lineno].Children = inner_dir

				// log.Debugf("inner dir: %+#v", inner_dir)
				// If matching data is available enrich the tree object with info from the yaml file
				for _, o := range(inner_dir) {
					for _, typefile := range(typefiles) {
						if strings.HasSuffix(o.Path, typefile) {
							gitPath, err := exec.LookPath("git")
							cmd := exec.Command(gitPath, "show", fmt.Sprintf("%s:%s", ref, o.Path))
							cwd := barePath(repo)
							cmd.Dir = cwd
							out, err := cmd.Output()
							if err != nil {
								return nil, fmt.Errorf("Error when trying to obtain file %s on ref %s of repository %s (%s) (%s).", path, ref, repo, err, err.(*exec.ExitError).Stderr,)
							}

							yaml.Unmarshal([]byte(out), &yaml_object)
							//log.Debugf("yaml is: %#v", yaml_object)

							for top_key,v := range(yaml_object){
								if v != nil {
									//log.Debugf("object is: %#v", v)
									switch v := v.(type) {
									default:  // Ignore types we do not expect
									case map[interface{}]interface{}:
										for key, value := range (v) {
											switch  {
											case key == "uuid":
												objects[lineno].Object_identifier = value.(string)
												objects[lineno].Object_type = top_key
												objects[lineno].Object_configfile = o.Path

											case key == "description":
												objects[lineno].Object_description = value.(string)
											case key == "name":
												objects[lineno].Object_name = value.(string)
											//case key == "type":
											//	objects[lineno].Object_type = value.(string)
											}
										}
									}
									if objects[lineno].Object_name == "My First Playground" {
										log.Debugf("object is: %#v\n\n\n", v)
										log.Debugf("out: %q\n\n\n", out)


									}
								}
							}


						}
					}
				}
			}
		}
	//objects[lineno] = line
	}
	return objects, err
}

func listdir(repo, ref, path string) ([]Leaf, error) {

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("Error when trying to find tree %s on ref %s of repository %s (%s).", path, ref, repo, err)
	}
	cwd := barePath(repo)
	repoExists, err := exists(cwd)
	if err != nil || !repoExists {
		return nil, fmt.Errorf("Error when trying to obtain tree %s on ref %s of repository %s (Repository does not exist).", path, ref, repo)
	}
	//var tree_parameter string

	//tree_parameter = "" // do not recurse
	cmd := exec.Command(gitPath, "ls-tree", ref, path) // also show tree objects

	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		log.Debugf("Command: %v", cmd)
		log.Debugf("Output: %v", out)
		log.Debugf("Error: %v", err)

		return nil, fmt.Errorf("Error when trying to execute ls-tree %s in %s on ref %s of repository %s (%s). '%s'", path, cmd.Dir, ref, repo, err, err.Error())
	}

	log.Debugf("Output: %q", out)
	log.Debugf("tree_parameter in listdir: ref: %s path: %s", ref, path)
	lines := strings.Split(string(out), "\n")
	objectCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		objectCount++
	}
	objects := make([]Leaf, objectCount)
	objectCount = 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tabbed := strings.Split(line, "\t")
		meta, filepath := tabbed[0], tabbed[1]
		meta_parts := strings.Split(meta, " ")
		permission, filetype, hash := meta_parts[0], meta_parts[1], meta_parts[2]
		var object Leaf
		object.Permission = permission
		object.Filetype = filetype
		object.Hash = hash
		object.Path = strings.TrimSpace(strings.Trim(filepath, "\""))
		object.RawPath = filepath
		objects[objectCount] = object
		objectCount++
	}
	log.Debugf("lines: %v", lines)
	log.Debugf("objects: %v", objects)

	return objects, nil
}

func retriever() ContentRetriever {
	if Retriever == nil {
		Retriever = &GitContentRetriever{}
	}
	return Retriever
}

// GetFileContents returns the contents for a given file
// in a given ref for the specified repository
func GetFileContents(repo, ref, path string) ([]byte, error) {
	return retriever().GetContents(repo, ref, path)
}

// SetFileContents uploads and commits the contents for a given file
// in a given ref for the specified repository
func SetFileContents(repo, path string, content []byte, commit GitCommit) (string, error) {
	return retriever().SetContents(repo, path, content, commit)
}

// DeleteFile removes a file from the repository (not from history!) and commits the removal
// in a given ref for the specified repository
func DeleteFile(repo, path string, commit GitCommit) (string, error) {
	return retriever().DeleteFile(repo, path, commit)
}

// GetArchive returns the contents for a given file
// in a given ref for the specified repository
func GetArchive(repo, ref string, format ArchiveFormat) ([]byte, error) {
	return retriever().GetArchive(repo, ref, format)
}

func GetTree(repo, ref, path, mode string) ([]map[string]string, error) {
	return retriever().GetTree(repo, ref, path, mode)
}

func GetForEachRef(repo, pattern string) ([]Ref, error) {
	return retriever().GetForEachRef(repo, pattern)
}

func GetBranches(repo string) ([]Ref, error) {
	return retriever().GetBranches(repo)
}

func GetDiff(repo, previousCommit, lastCommit string) ([]byte, error) {
	return retriever().GetDiff(repo, previousCommit, lastCommit)
}

func GetTags(repo string) ([]Ref, error) {
	return retriever().GetTags(repo)
}

func TempClone(repo string) (string, func(), error) {
	return retriever().TempClone(repo)
}

func Checkout(cloneDir, branch string, isNew bool) error {
	return retriever().Checkout(cloneDir, branch, isNew)
}

func AddAll(cloneDir string) error {
	return retriever().AddAll(cloneDir)
}

func Commit(cloneDir, message string, author, committer GitUser) error {
	return retriever().Commit(cloneDir, message, author, committer)
}

func Push(cloneDir, branch string) error {
	return retriever().Push(cloneDir, branch)
}

func CommitZip(repo string, z *multipart.FileHeader, c GitCommit) (*Ref, error) {
	return retriever().CommitZip(repo, z, c)
}

func GetLogs(repo, hash string, total int, path string) (*GitHistory, error) {
	return retriever().GetLogs(repo, hash, total, path)
}

type InvalidRepositoryError struct {
	message string
}

func (err *InvalidRepositoryError) Error() string {
	return err.message
}

// Vitruvius specific tree function

func GetTreeVitruvius(repo, ref, path, mode string, typefiles []string) ([]Leaf, error) {
	return retriever().GetTreeVitruvius(repo, ref, path, mode, typefiles)
}