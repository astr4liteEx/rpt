package plugin

import (
	"encoding/json/v2"

	"github.com/astr4liteEx/rpt/sdk"
)

func descWith(schemas string) sdk.Description {
	var s sdk.Schemas
	if err := json.Unmarshal([]byte(schemas), &s); err != nil {
		panic(err)
	}
	return sdk.Description{Schemas: &s}
}
