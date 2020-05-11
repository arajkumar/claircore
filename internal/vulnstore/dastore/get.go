package dastore

import (
	"context"
	"fmt"

	//"strconv"

	"github.com/rs/zerolog"

	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

type Cvee struct {
	Cve_id   []string `json:"cve_id"`
	Fixed_in []string `json:"fixed_in"`
}

type Data struct {
	Cvee Cvee `json:"cve"`
}

//Creating a structre for json
type Cve struct {
	Idd  string  `json:"id"`
	Cvss float32 `json:"cvss"`
}

//Creating a structre for json
type ComponentAnalysis struct {
	Cve []Cve `json:"cve"`
}

//Creating a structre for json
type Recommendation struct {
	ChangeTo          string            `json:"change_to"`
	Message           string            `json:"message"`
	ComponentAnalysis ComponentAnalysis `json:"component-analyses"`
}

//Creating a structre for json
type Result struct {
	Recommendation Recommendation `json:"recommendation"`
	Data           []Data         `json:"data"`
}

//Report Creating a structre for json
type Report struct {
	Result Result `json:"result"`
}

func get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/get").
		Logger()
	ctx = log.WithContext(ctx)

	s1 := "https://f8a-analytics-2445582058137.production.gw.apicast.io/api/v1/component-analyses/pypi/"
	s2 := "?user_key=9e7da76708fe374d8c10fa752e72989f"

	results := make(map[string][]*claircore.Vulnerability)
	//position := 0

	for _, j := range records {
		log.Print(j)
		//dynamically creating the package
		url := s1 + j.Package.Name + "/" + j.Package.Version + s2

		resultjson, _ := http.Get(url)

		body, _ := ioutil.ReadAll(resultjson.Body)
		fmt.Println(string(body))
		reports := Report{}
		err := json.Unmarshal(body, &reports)

		if err != nil {
			fmt.Println(err)
		}

		if len(reports.Result.Recommendation.ComponentAnalysis.Cve) > 0 {

			v := &claircore.Vulnerability{

				ID:                 j.Package.ID,
				Updater:            "",
				Name:               reports.Result.Recommendation.ComponentAnalysis.Cve[0].Idd,
				Description:        reports.Result.Recommendation.Message,
				Links:              "",
				Severity:           fmt.Sprint(reports.Result.Recommendation.ComponentAnalysis.Cve[0].Cvss),
				// NormalizedSeverity: "",
				FixedInVersion:     reports.Result.Data[0].Cvee.Fixed_in[0],
				Package: &claircore.Package{ID: "0",
					Name:    "xyz",
					Version: "v0.0"},
				Dist: &claircore.Distribution{},
				Repo: &claircore.Repository{},
			}

			//key := strconv.Itoa(position)

			results[j.Package.ID] = append(results[j.Package.ID], v)

			//position = position + 1
		}

		fmt.Printf("%v %v", j.Package.Name, j.Package.Version)

	}

	return results, nil

}
