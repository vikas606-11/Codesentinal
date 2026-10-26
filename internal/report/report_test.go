package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

func sampleData() Data {
	return Data{
		MSPName: "Example MSP", ClientName: "Example Retail Ltd",
		GeneratedAt: time.Now(), Scope: "account", Status: "draft", Version: 1,
		Account: "123456789012", Regions: []string{"us-east-1"},
		Score: 72, Rating: "Needs Improvement",
		Changes: types.Changes{NewCount: 3, FixedCount: 2, RegressedCount: 1},
		TopFixes: []TopFix{
			{Finding: types.Finding{Title: "SSH open to the world", Severity: types.SevCritical, RiskScore: 94, Region: "us-east-1"}},
		},
		ByService: []ServiceGroup{
			{Service: "ec2", Findings: []types.Finding{{Title: "SSH open", Severity: types.SevCritical, RiskScore: 94, Status: types.StatusOpen}}},
		},
		Summary: "The account scored 72/100 (Needs Improvement).",
	}
}

func TestMarkdownHasNumbers(t *testing.T) {
	md := string(RenderMarkdown(sampleData()))
	for _, want := range []string{"72 / 100", "SSH open to the world", "New: 3", "Fixed: 2"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestHTMLHasSameNumbers(t *testing.T) {
	html := string(RenderHTML(sampleData()))
	for _, want := range []string{"72 / 100", "SSH open", "Needs Improvement"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestDOCXValidZipWithParts(t *testing.T) {
	b, err := RenderDOCX(sampleData())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a valid zip: %v", err)
	}
	required := map[string]bool{
		"[Content_Types].xml": false, "_rels/.rels": false,
		"word/document.xml": false, "word/styles.xml": false, "docProps/core.xml": false,
		"word/_rels/document.xml.rels": false,
	}
	var docXML []byte
	for _, f := range zr.File {
		if _, ok := required[f.Name]; ok {
			required[f.Name] = true
		}
		rc, _ := f.Open()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(rc)
		rc.Close()
		// every XML part must parse
		if strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels") {
			if err := xml.Unmarshal(buf.Bytes(), new(any)); err != nil {
				// any-unmarshal is lax; use a decoder token walk instead
				dec := xml.NewDecoder(bytes.NewReader(buf.Bytes()))
				for {
					_, e := dec.Token()
					if e != nil {
						if e.Error() != "EOF" {
							t.Errorf("%s not well-formed xml: %v", f.Name, e)
						}
						break
					}
				}
			}
		}
		if f.Name == "word/document.xml" {
			docXML = buf.Bytes()
		}
	}
	for name, found := range required {
		if !found {
			t.Errorf("missing required part %s", name)
		}
	}
	if !strings.Contains(string(docXML), "72 / 100") {
		t.Error("docx document.xml missing the score figure")
	}
	if !strings.Contains(string(docXML), "SSH open to the world") {
		t.Error("docx missing top finding")
	}
}

func TestWorkflowTransitions(t *testing.T) {
	if _, err := Transition(StatusDraft, "submit", "Alice", ""); err != nil {
		t.Fatalf("draft->submit should work: %v", err)
	}
	if _, err := Transition(StatusDraft, "submit", "", ""); err == nil {
		t.Fatal("submit without reviewer should fail")
	}
	if _, err := Transition(StatusApproved, "reject", "", "x"); err == nil {
		t.Fatal("cannot transition an approved report")
	}
	if _, err := Transition(StatusInReview, "reject", "Alice", ""); err == nil {
		t.Fatal("reject requires a note")
	}
	st, err := Transition(StatusInReview, "approve", "Alice", "")
	if err != nil || st != StatusApproved {
		t.Fatalf("in_review->approve failed: %v %s", err, st)
	}
}
