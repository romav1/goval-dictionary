package commands

import (
	"context"
	"encoding/xml"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/google/subcommands"
	"github.com/inconshreveable/log15"
	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/kotakanbe/goval-dictionary/fetcher"
	"github.com/kotakanbe/goval-dictionary/models"
	"github.com/kotakanbe/goval-dictionary/util"
	"github.com/ymomoi/goval-parser/oval"

	//"fmt"
)

// FetchScanovalCmd is Subcommand for fetch RedHat OVAL
type FetchScanovalCmd struct {
	LogDir  string
	LogJSON bool
}

// Name return subcommand name
func (*FetchScanovalCmd) Name() string { return "fetch-scanoval" }

// Synopsis return synopsis
func (*FetchScanovalCmd) Synopsis() string { return "Fetch Vulnerability dictionary from BDU" }

// Usage return usage
func (*FetchScanovalCmd) Usage() string {
	return `fetch-scanoval:
	fetch-scanoval
		[-dbtype=sqlite3|mysql|postgres|redis]
		[-dbpath=$PWD/oval.sqlite3 or connection string]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-no-details]
		[-log-dir=/path/to/log]
		[-log-json]

For the first time, run the below command to fetch data for all versions.
	$ goval-dictionary fetch-scanoval

`
}

// SetFlags set flag
func (p *FetchScanovalCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "quiet mode (no output)")
	f.BoolVar(&c.Conf.NoDetails, "no-details", false, "without vulnerability details")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&p.LogJSON, "log-json", false, "output log as JSON")

	pwd := os.Getenv("PWD")
	f.StringVar(&c.Conf.DBPath, "dbpath", pwd+"/oval.sqlite3",
		"/path/to/sqlite3 or SQL connection string")

	f.StringVar(&c.Conf.DBType, "dbtype", "sqlite3",
		"Database type to store data in (sqlite3, mysql, postgres or redis supported)")

	f.StringVar(
		&c.Conf.HTTPProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)
}

// Execute execute
func (p *FetchScanovalCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.SetLogger(p.LogDir, c.Conf.Quiet, c.Conf.Debug, p.LogJSON)
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}
	/*

	if len(f.Args()) == 0 {
		log15.Error("Specify versions to fetch")
		return subcommands.ExitUsageError
	}*/

	driver, locked, err := db.NewDB(c.Ubuntu, c.Conf.DBType, c.Conf.DBPath, c.Conf.DebugSQL)
	if err != nil {
		if locked {
			log15.Error("Failed to open DB. Close DB connection before fetching", "err", err)
			return subcommands.ExitFailure
		}
		log15.Error("Failed to open DB", "err", err)
		return subcommands.ExitFailure
	}

	// Distinct
	v := map[string]bool{}
	vers := []string{}
	for _, arg := range f.Args() {
		v[arg] = true
	}
	for k := range v {
		vers = append(vers, k)
	}

	results, err := fetcher.FetchScanovalFiles(vers)
	//fmt.Printf("\nresults = %#v\n", results)
	if err != nil {
		log15.Error("Failed to fetch files", "err", err)
		return subcommands.ExitFailure
	}

	for _, r := range results {
		ovalroot := oval.Root{}
		if err = xml.Unmarshal(r.Body, &ovalroot); err != nil {
			log15.Error("Failed to unmarshal", "url", r.URL, "err", err)
			return subcommands.ExitUsageError
		}
		log15.Info("Fetched", "URL", r.URL, "OVAL definitions", len(ovalroot.Definitions.Definitions))

		defs := models.ConvertScanovalToModel(&ovalroot)

		var timeformat = "2006-01-02T15:04:05"
		t, err := time.Parse(timeformat, ovalroot.Generator.Timestamp)
		if err != nil {
			log15.Error("Failed to parse time", "err", err)
			return subcommands.ExitFailure
		}

		root := models.Root{
			Family:      c.Debian,
			OSVersion:   r.Target,
			Definitions: defs,
			Timestamp:   time.Now(),
		}

		ss := strings.Split(r.URL, "/")
		fmeta := models.FetchMeta{
			Timestamp: t,
			FileName:  ss[len(ss)-1],
		}

		if err := driver.InsertOval(c.Ubuntu, &root, fmeta); err != nil {
			log15.Error("Failed to insert OVAL", "err", err)
			return subcommands.ExitFailure
		}
		if err := driver.InsertFetchMeta(fmeta); err != nil {
			log15.Error("Failed to insert meta", "err", err)
			return subcommands.ExitFailure
		}
		log15.Info("Finish", "Updated", len(root.Definitions))
	}

	return subcommands.ExitSuccess
}
