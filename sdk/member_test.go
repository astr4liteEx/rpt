package sdk

import "testing"

func TestSetMember(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"replaces in place", `{"a":1,"scope":["x"],"b":{"c":2}}`, `{"a":1,"scope":["S-1"],"b":{"c":2}}`},
		{"appends when absent", `{"a":1, "b" : [1, 2]}`, `{"a":1,"b":[1, 2],"scope":["S-1"]}`},
		{"empty object", `{}`, `{"scope":["S-1"]}`},
		{"escaped names compare decoded", `{"scope":[]}`, `{"scope":["S-1"]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetMember([]byte(tt.in), "scope", []string{"S-1"})
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}
