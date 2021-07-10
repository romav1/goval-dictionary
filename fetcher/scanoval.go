package fetcher

import (
	"fmt"
)

func newScanovalFetchRequests(target []string) (reqs []fetchRequest) {
	const t = "https://bdu.fstec.ru/files/scanoval.xml"

	reqs = make([]fetchRequest, 0)

	reqs = append(reqs, fetchRequest{
			target:       "1",
			url:          t,
			concurrently: false,
			bzip2:        false,
		})
	fmt.Println(reqs)
	return reqs
}


// FetchScanovalFiles fetch OVAL from Scanoval
func FetchScanovalFiles(versions []string) ([]FetchResult, error) {

	fmt.Printf("\nTrying to fetch SCANOVAL...\n")
	reqs := newScanovalFetchRequests(versions)
	if len(reqs) == 0 {
		return nil,
			fmt.Errorf("There are no versions to fetch")
	}
	results, err := fetchFeedFiles(reqs)
	//fmt.Printf("\nResults: %#v\n", results)
	if err != nil {
		return nil,
			fmt.Errorf("Failed to fetch. err: %s", err)
	}
	return results, nil
}
