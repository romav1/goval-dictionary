package models

import (
	"strings"

	c "github.com/kotakanbe/goval-dictionary/config"
	"github.com/ymomoi/goval-parser/oval"
)

// ConvertScanovalToModel Convert OVAL to models
func ConvertScanovalToModel(root *oval.Root) (defs []Definition) {
	for _, d := range root.Definitions.Definitions {
		if strings.Contains(d.Description, "** REJECT **") {
			continue
		}
		cveID := ""
		rs := []Reference{}
		for _, r := range d.References {
			rs = append(rs, Reference{
				Source: r.Source,
				RefID:  r.RefID,
				RefURL: r.RefURL,
			})
			if r.Source == "CVE" {
				cveID = r.RefID
			}
		}

		for _, r := range d.Advisory.Refs {
			rs = append(rs, Reference{
				Source: "Ref",
				RefURL: r.URL,
			})
		}

		for _, r := range d.Advisory.Bugs {
			rs = append(rs, Reference{
				Source: "Bug",
				RefURL: r.URL,
			})
		}

		def := Definition{
			DefinitionID: d.ID,
			Title:        d.Title,
			Description:  d.Description,
			Advisory: Advisory{
				Severity: d.Advisory.Severity,
			},
			Debian:        Debian{CveID: cveID},
			AffectedPacks: collectScanovalPacks(d.Criteria),
			References:    rs,
		}

		if c.Conf.NoDetails {
			def.Title = ""
			def.Description = ""
			def.Advisory = Advisory{}

			var references []Reference
			for _, ref := range def.References {
				if ref.Source != "CVE" {
					continue
				}
				references = append(references, Reference{
					Source: ref.Source,
					RefID:  ref.RefID,
				})
			}
			def.References = references
		}

		defs = append(defs, def)
	}
	return
}

func collectScanovalPacks(cri oval.Criteria) []Package {
	return walkScanoval(cri, []Package{})
}

func walkScanoval(cri oval.Criteria, acc []Package) []Package {
	for _, c := range cri.Criterions {
		if c.Negate {
			continue
		}

		if pkg, ok := parseNotFixedYet(c.Comment); ok {
			acc = append(acc, *pkg)
		}
		if pkg, ok := parseNotDecided(c.Comment); ok {
			acc = append(acc, *pkg)
		}
		if pkg, ok := parseFixed(c.Comment); ok {
			acc = append(acc, *pkg)
		}

		// nop for now
		// <criterion test_ref="oval:com.ubuntu.xenial:tst:10" comment="The vulnerability of the 'brotli' package in xenial is not known (status: 'needs-triage'). It is pending evaluation." />
		// <criterion test_ref="oval:com.ubuntu.bionic:tst:201211480000000" comment="apache2: while related to the CVE in some way, a decision has been made to ignore this issue (note: 'code-not-compiled')." />

	}

	if len(cri.Criterias) == 0 {
		return acc
	}
	for _, c := range cri.Criterias {
		acc = walkScanoval(c, acc)
	}
	return acc
}


