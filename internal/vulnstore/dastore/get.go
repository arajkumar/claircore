package dastore

import (
	"context"
	"fmt"
    "bytes"
	//"strconv"
    "sync"
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
	Package string `json:"package"`
	Version string `json:"version"`
}

func call(req []Request,ids []string, results map[string][]*claircore.Vulnerability, wg *sync.WaitGroup){

	fmt.Println("Inside call")
   jsonValue, _ := json.Marshal(req)
   // fmt.Println(jsonValue)
	response, err := http.Post("https://f8a-analytics-2445582058137.production.gw.apicast.io:443/api/v1/component-analyses/?user_key=9e7da76708fe374d8c10fa752e72989f", "application/json", bytes.NewBuffer(jsonValue))
	 if err != nil {
		 fmt.Printf("The HTTP request failed with error %s\n", err)
	 } else {
		 fmt.Println("HII")
		 var da_response []Report
 
		
		 data, _ := ioutil.ReadAll(response.Body)
	//	 fmt.Println(len(data),id)
 
		  err = json.Unmarshal(data, &da_response)
		 if err != nil {
			 fmt.Println(err)
		 }
	//     fmt.Println(len(da_response))
 
	  //   fmt.Println(da_response[0])
 
	fmt.Println("Printing length of data ",len(data))


	  for i:=0;i<len(ids);i++{

          
		 	          if len(da_response[i].Result.Recommendation.ComponentAnalysis.Cve)>0 {

					//	var v *claircore.Vulnerability
						fmt.Println("Printing cve array ",da_response[i].Result.Recommendation.ComponentAnalysis.Cve)
                         var vulnArray []*claircore.Vulnerability

				//		for k:=0;k<len(da_response[i].Result.Recommendation.ComponentAnalysis.Cve);k++{
					//		fmt.Println("Inside ", da_response[i].Result.Recommendation.ComponentAnalysis.Cve[k].Idd)
						  vulnArray=append(vulnArray,&claircore.Vulnerability{
						ID:                 ids[i],
							Updater:            "",
				 			Name:               da_response[i].Result.Recommendation.ComponentAnalysis.Cve[0].Idd,
							Description:        da_response[i].Result.Recommendation.Message,
	 					Links:              "",
		 	 			Severity:           fmt.Sprint(da_response[i].Result.Recommendation.ComponentAnalysis.Cve[0].Cvss),
							// NormalizedSeverity: "",
				 			FixedInVersion:     da_response[i].Result.Data[0].Cvee.Fixed_in[0],
			 			Package: &claircore.Package{ID: "0",
				 				Name:    "xyz",
								Version: "v0.0"},
						Dist: &claircore.Distribution{},
						Repo: &claircore.Repository{},
				  })

					  results[ids[i]] = vulnArray
					}
				 
			   }
	 }
 
	 wg.Done()
 
  }


func get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/dastore/get").
		Logger()
	ctx = log.WithContext(ctx)


	fmt.Println("Inside DA Store")
     fmt.Println(len(records))


	// s1 := "https://f8a-analytics-2445582058137.production.gw.apicast.io/api/v1/component-analyses/pypi/"
	// s2 := "?user_key=9e7da76708fe374d8c10fa752e72989f"

	results := make(map[string][]*claircore.Vulnerability)
	//position := 0

	 
	 iterations:=(len(records)/10)

	if (len(records)%10 == 0){
		iterations=iterations+0
	}else{
		iterations=iterations+1
	}
//	+((len(records)%10)==0 ? 0 : 1)
	
	total_records:=len(records)

	for i:=0;i<iterations;i++{

		var req []Request
	  
		  start_record:=i*10
      //    start_record:=0
		  var end_record int

		  if total_records>=10{
			  end_record=start_record+9
		  }else{
			  end_record=start_record + total_records -1
		  }

		  if total_records>=10{
			  total_records=total_records-10
	  
		  }else{
			  total_records=0
		  }

		var ids []string
			 for record:=start_record;record<=end_record;record++{

			 req=append(req,Request{Ecosystem: "pypi",Package: records[record].Package.Name, Version: records[record].Package.Version})   
			 ids=append(ids,records[record].Package.ID)   
			  
		  }


			
			



		  var wg sync.WaitGroup

		  wg.Add(1)

		 go call(req,ids,results,&wg)
		 
		 wg.Wait()


		
			fmt.Println("Iteration ",i)
		//    fmt.Println((da_response))
	 
		   // fmt.Println(da_response[0])
		}

		
		     



	return results, nil

}
