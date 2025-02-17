// Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not
// use this file except in compliance with the License. A copy of the
// License is located at
//
// http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing
// permissions and limitations under the License.

// package parameters provides utilities to parse ssm document parameters
package parameters

import (
	"fmt"
	"testing"

	"github.com/aws/amazon-ssm-agent/agent/mocks/log"
	"github.com/stretchr/testify/assert"
)

var logger = log.NewMockLog()

type IsSingleParameterStringTest struct {
	Input     string
	ParamName string
	Result    bool
}

func TestIsSingleParameterString(t *testing.T) {
	isSingleParameterStringTests := []IsSingleParameterStringTest{
		{"{{ command}}", "command", true},
		{"{{ comm}}", "command", false},
		{"{{ command }}", "com", false},
		{"a {{ command}}", "command", false},
		{"{{ command }} {{ command }}", "command", false},
		{"{{ co!mmand}}", "co!mmand", false},
	}

	for _, test := range isSingleParameterStringTests {
		r := isSingleParameterString(test.Input, test.ParamName)
		assert.Equal(t, test.Result, r)
	}
}

type ValidateNameTest struct {
	ParamName string
	Result    bool
}

func TestValidateName(t *testing.T) {
	validateNameTests := []ValidateNameTest{
		{"runCommand", true},
		{"run+Command", false},
		{"runComand12", true},
		{"run Command", false},
		{"runCommand??", false},
	}

	for _, test := range validateNameTests {
		r := validName(test.ParamName)
		assert.Equal(t, test.Result, r)
	}
}

type ReplaceParamTestCase struct {
	Input  interface{}
	Params map[string]interface{}
	Output interface{}
}

func TestReplaceParameter_SingleOccurrence(t *testing.T) {
	parameters := map[string]interface{}{
		"p1": "name",
	}
	assert.Equal(t, "A name",
		ReplaceParameter("A {{ p1 }}", parameters, nil))
}

func TestReplaceParameter_MultipleOccurrences(t *testing.T) {
	parameters := map[string]interface{}{
		"p1": "name",
	}
	assert.Equal(t, "A name is a name",
		ReplaceParameter("A {{p1 }} is a {{ p1}}", parameters, nil))
}

func TestReplaceParameter_EscapesDollarSignsToAvoidBackreferences(t *testing.T) {
	parameters := map[string]interface{}{
		"Path": "C:\\$Recycle.Bin",
	}
	assert.Equal(t, "Write-Host 'C:\\$Recycle.Bin'",
		ReplaceParameter("Write-Host '{{Path}}'", parameters, nil))
}

func TestReplaceParameter_LeavesEscapedDollarSigns(t *testing.T) {
	parameters := map[string]interface{}{
		"Path": "C:\\$$Recycle.Bin",
	}
	assert.Equal(t, "Write-Host 'C:\\$Recycle.Bin'",
		ReplaceParameter("Write-Host '{{ Path }}'", parameters, nil))
}

func TestReplaceParameter_embedded_parameter(t *testing.T) {
	parameters := map[string]interface{}{
		"p1": "{{p2}}",
		"p2": "p2-value",
	}
	assert.Equal(t, " we have embedded {{p2}} and p2-value, should not see 2 p2-value in result",
		ReplaceParameter(" we have embedded {{p1}} and {{p2}}, should not see 2 {{p2}} in result", parameters, nil))
}

func TestReplaceParameter_novalue_parameter(t *testing.T) {
	parameters := map[string]interface{}{
		"p1": "p1-value",
		"p2": "p2-value",
	}
	assert.Equal(t, " we have p1-value and p2-value, but no {{p3}}",
		ReplaceParameter(" we have {{p1}} and {{p2}}, but no {{p3}}", parameters, nil))
}

func TestReplaceParameter_start_and_end(t *testing.T) {

	parameters := map[string]interface{}{
		"p1": "p1-value",
		"p2": "p2-value",
	}
	assert.Equal(t, "p1-value and p2-value",
		ReplaceParameter("{{p1}} and {{p2}}", parameters, nil))
}

func TestReplaceParameter_no_parameter(t *testing.T) {

	parameters := map[string]interface{}{
		"p1": "p1-value",
		"p2": "p2-value",
	}
	assert.Equal(t, "there is no parameter",
		ReplaceParameter("there is no parameter", parameters, nil))
}

func TestReplaceParameter_json(t *testing.T) {
	type testStructure struct {
		S string
		I int
	}
	parameters := map[string]interface{}{
		"p1": "p1-value",
		"p2": testStructure{S: "p2-string", I: 10},
	}
	assert.Equal(t, `p1-value and {"S":"p2-string","I":10}`,
		ReplaceParameter("{{p1}} and {{p2}}", parameters, nil))
}

func TestReplaceParameters(t *testing.T) {
	testCases := generateReplaceParamTestCases()
	for _, testCase := range testCases {
		assert.Equal(t, testCase.Output, ReplaceParameters(testCase.Input, testCase.Params, logger))
	}
}

func generateReplaceParamTestCases() []ReplaceParamTestCase {
	params := map[string]interface{}{
		"param1": "a parameter",
		"param2": []string{"a", "plane"},
		"param3": 5,
	}

	var testCases []ReplaceParamTestCase

	// test cases for replacement in parameter-only strings
	for paramName, paramValue := range params {
		testCases = append(testCases, ReplaceParamTestCase{
			Input:  fmt.Sprintf("{{ %v }}", paramName),
			Params: params,
			Output: paramValue,
		})
	}

	// test cases for replacement in strings that have parameter inside other text
	for paramName, paramValue := range params {
		v, _ := convertToString(paramValue)
		testCases = append(testCases, ReplaceParamTestCase{
			Input:  fmt.Sprintf("put {{ %v }} here", paramName),
			Params: params,
			Output: fmt.Sprintf("put %v here", v),
		})
	}

	// test case for unexpected types
	unexp := struct{ Field string }{Field: "no {{ param1 }} replacement here"}
	testCases = append(testCases, ReplaceParamTestCase{
		Input:  unexp,
		Params: params,
		Output: unexp,
	})

	// test cases for deeper hierarchies
	for i := 0; i < 3; i++ {
		// test case for slice
		testCases = append(testCases, ReplaceParamTestCase{
			Input:  collectInputs(testCases),
			Params: params,
			Output: collectOutputs(testCases),
		})

		// test case for map
		testCases = append(testCases, ReplaceParamTestCase{
			Input: map[string]interface{}{
				"one":   collectInputs(testCases),
				"two":   5,
				"three": true,
			},
			Params: params,
			Output: map[string]interface{}{
				"one":   collectOutputs(testCases),
				"two":   5,
				"three": true,
			},
		})
	}

	// test case for slice of maps
	testCases = append(testCases, sliceOfMapsTestCase())

	return testCases
}

func sliceOfMapsTestCase() ReplaceParamTestCase {
	in := []map[string]interface{}{
		{
			"workingDirectory": "{{ workingDirectory }}",
			"timeoutSeconds":   "{{ timeoutSeconds }}",
			"runCommand":       "{{ runCommand }}",
			"id":               "0.aws:runScript",
		},
	}
	params := map[string]interface{}{
		"workingDirectory": "",
		"runCommand":       []interface{}{"echo hello; ls; whoami;"},
	}
	out := []map[string]interface{}{
		{
			"workingDirectory": "",
			"timeoutSeconds":   "{{ timeoutSeconds }}",
			"runCommand":       params["runCommand"],
			"id":               "0.aws:runScript",
		},
	}

	return ReplaceParamTestCase{
		Input:  in,
		Params: params,
		Output: out,
	}
}

func collectInputs(testCases []ReplaceParamTestCase) []interface{} {
	var result []interface{}
	for _, testCase := range testCases {
		result = append(result, testCase.Input)
	}
	return result
}

func collectOutputs(testCases []ReplaceParamTestCase) []interface{} {
	var result []interface{}
	for _, testCase := range testCases {
		result = append(result, testCase.Output)
	}
	return result
}

func TestConvertToString(t *testing.T) {
	type testCase struct {
		Input  interface{}
		Output string
	}

	testCases := []testCase{
		{
			Input:  "a parameter",
			Output: "a parameter",
		},
		{
			Input:  []string{"a", "plane"},
			Output: `["a","plane"]`,
		},
		{
			Input:  5,
			Output: "5",
		},
	}

	for _, tst := range testCases {
		actual, err := convertToString(tst.Input)
		assert.NoError(t, err)
		assert.Equal(t, tst.Output, actual)
	}
}

func TestConvertToBool(t *testing.T) {
	type testCase struct {
		Input  interface{}
		Output bool
	}

	testCases := []testCase{
		{
			Input:  false,
			Output: false,
		},
		{
			Input:  "true",
			Output: true,
		},
		{
			Input:  "",
			Output: false,
		},
		{
			Input:  nil,
			Output: false,
		},
	}
	for _, tst := range testCases {
		actual, err := ConvertToBool(tst.Input)
		assert.NoError(t, err)
		assert.Equal(t, tst.Output, actual)
	}

	var err error
	// test of invalid input
	_, err = ConvertToBool("invalid input")
	assert.NotNil(t, err)

	// test of invalid parameter type
	_, err = ConvertToBool(1)
	assert.NotNil(t, err)
}
