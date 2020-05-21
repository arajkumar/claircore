package dastore

import (
	"bytes"
	"context"
	"fmt"
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

type Request struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

type ReportsId struct {
	Response []Report
	//	Ids []string
	startInd int
}

func call(req []Request, startInd int, c chan ReportsId) {

	fmt.Println("Inside call")
	jsonValue, _ := json.Marshal(req)
	response, err := http.Post("https://f8a-analytics-2445582058137.production.gw.apicast.io:443/api/v1/component-analyses/?user_key=9e7da76708fe374d8c10fa752e72989f", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		var da_response []Report
		data, _ := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(data, &da_response)
		if err != nil {
			fmt.Println(err)
		}
		result := ReportsId{Response: da_response, startInd: startInd}
		c <- result
	}
}

func get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/dastore/get").
		Logger()
	ctx = log.WithContext(ctx)
	results := make(map[string][]*claircore.Vulnerability)
	iterations := (len(records) / 10)
	if len(records)%10 == 0 {
		iterations = iterations + 0
	} else {
		iterations = iterations + 1
	}
	total_records := len(records)
	ch := make(chan ReportsId, iterations-1)
	for i := 0; i < iterations; i++ {
		var req []Request
		start_record := i * 10
		var end_record int
		if total_records >= 10 {
			end_record = start_record + 9
		} else {
			end_record = start_record + total_records - 1
		}
		if total_records >= 10 {
			total_records = total_records - 10
		} else {
			total_records = 0
		}
		for record := start_record; record <= end_record; record++ {
			req = append(req, Request{Ecosystem: "pypi", Package: records[record].Package.Name, Version: records[record].Package.Version})
		}
		go call(req, start_record, ch)
	}

	for i := 0; i < iterations; i++ {
		ans := <-ch
		fmt.Println("Printing response ", ans.startInd)
		offset := ans.startInd
		response := ans.Response
		for i := 0; i < len(response); i++ {
			if len(response[i].Result.Recommendation.ComponentAnalysis.Cve) > 0 {
				var vulnArray []*claircore.Vulnerability
				vulnArray = append(vulnArray, &claircore.Vulnerability{
					ID:          records[i+offset].Package.ID,
					Updater:     "",
					Name:        response[i].Result.Recommendation.ComponentAnalysis.Cve[0].Idd,
					Description: response[i].Result.Recommendation.Message,
					Links:       "",
					Severity:    fmt.Sprint(response[i].Result.Recommendation.ComponentAnalysis.Cve[0].Cvss),
					// 						// NormalizedSeverity: "",
					FixedInVersion: response[i].Result.Data[0].Cvee.Fixed_in[0],
					Package: &claircore.Package{ID: "0",
						Name:    "xyz",
						Version: "v0.0"},
					Dist: &claircore.Distribution{},
					Repo: &claircore.Repository{},
				})

				results[records[i+offset].Package.ID] = vulnArray
			}

		}

	}

	return results, nil

}
