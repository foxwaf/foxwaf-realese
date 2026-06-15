package acmatch

import (
	"sort"
	"testing"
)

func sorted(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func eq(a, b []string) bool {
	a, b = sorted(a), sorted(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- AC 自动机 ----

func TestTrieBasic(t *testing.T) {
	tr := NewTrie(true)
	tr.Add("r1", "select")
	tr.Add("r2", "union")
	tr.Add("r3", "from")
	tr.Build()

	got := tr.Match("1 union select x from y")
	if !eq(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("got %v", got)
	}
	if got := tr.Match("nothing here"); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestTrieOverlapping(t *testing.T) {
	// 重叠 + 后缀关系：he / she / his / hers
	tr := NewTrie(true)
	tr.Add("he", "he")
	tr.Add("she", "she")
	tr.Add("his", "his")
	tr.Add("hers", "hers")
	tr.Build()
	// "ahishers": his(1-3), she(3-5), he(4-5), hers(4-7) 全部命中（重叠）。
	got := tr.Match("ahishers")
	if !eq(got, []string{"his", "she", "he", "hers"}) {
		t.Fatalf("got %v", got)
	}
}

func TestTrieCaseInsensitive(t *testing.T) {
	tr := NewTrie(false)
	tr.Add("r1", "SeLeCt")
	tr.Build()
	if got := tr.Match("xx SELECT yy"); !eq(got, []string{"r1"}) {
		t.Fatalf("got %v", got)
	}
	if got := tr.Match("xx select yy"); !eq(got, []string{"r1"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSharedLiteralMultiID(t *testing.T) {
	tr := NewTrie(true)
	tr.Add("a", "cmd")
	tr.Add("b", "cmd")
	tr.Build()
	if got := tr.Match("run cmd now"); !eq(got, []string{"a", "b"}) {
		t.Fatalf("got %v", got)
	}
}

// ---- 字面量提取 ----

func TestRequiredLiteral(t *testing.T) {
	cases := []struct {
		pat, want string
	}{
		{`select\s+.*\s+from`, "select"}, // 取最长必含（select 比 from 长）
		{`union\s+all\s+select`, "select"}, // select(6) > union(5) > all(3)
		{`(abc|def)`, ""},           // 或：无单一必含
		{`(?i)union`, ""},           // 折叠：大小写敏感模式下降级
		{`ab`, ""},                  // 过短
		{`/etc/passwd`, "/etc/passwd"},
		{`foo(bar)+baz`, "foo"},     // foo/bar/baz 同长，取先到的必含字面量
		{`x*payload`, "payload"},    // x* 可选，payload 必含
	}
	for _, c := range cases {
		if got := RequiredLiteral(c.pat); got != c.want {
			t.Errorf("RequiredLiteral(%q)=%q want %q", c.pat, got, c.want)
		}
	}
}

// ---- 正则集合预筛 ----

func TestRegexSet(t *testing.T) {
	s := NewRegexSet(false)
	must := func(id, pat string) {
		if err := s.Add(id, pat); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}
	must("sqli", `union\s+select`)
	must("path", `/etc/passwd`)
	must("alt", `(curl|wget)`) // 无单一字面量 -> always
	s.Build()

	// 命中 sqli
	if got := s.Match("a=1 UNION   SELECT 2"); !eq(got, []string{"sqli"}) {
		t.Fatalf("sqli got %v", got)
	}
	// 命中 always 列表里的 alt
	if got := s.Match("; wget http://x"); !eq(got, []string{"alt"}) {
		t.Fatalf("alt got %v", got)
	}
	// 字面量命中但正则不命中（有 union 无 select）-> 不应误报
	if got := s.Match("union of two sets"); got != nil {
		t.Fatalf("false positive: %v", got)
	}
	// 完全 benign
	if got := s.Match("hello world"); got != nil {
		t.Fatalf("benign got %v", got)
	}
}

func TestMightMatch(t *testing.T) {
	s := NewRegexSet(false)
	_ = s.Add("sqli", `union\s+select`)
	s.Build()
	if !s.MightMatch("xx union yy select zz") {
		t.Fatal("should be candidate")
	}
	if s.MightMatch("totally benign text") {
		t.Fatal("benign should fast-path to false")
	}
}

// ---- JSON / XML ----

func TestExtractJSON(t *testing.T) {
	got := ExtractJSONStrings([]byte(`{"name":"alice","tags":["x","y"],"n":1}`))
	want := []string{"name", "alice", "tags", "x", "y", "n"}
	if !eq(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExtractXML(t *testing.T) {
	got := ExtractXMLStrings([]byte(`<root attr="v"><item>text</item></root>`))
	want := []string{"root", "attr", "v", "item", "text"}
	if !eq(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// ---- 基准 ----

func buildBenchSet() *RegexSet {
	s := NewRegexSet(false)
	pats := []string{
		`union\s+select`, `/etc/passwd`, `<script>`, `\.\./\.\./`,
		`exec\s+xp_`, `concat\s*\(`, `or\s+1\s*=\s*1`, `benchmark\s*\(`,
	}
	for i, p := range pats {
		_ = s.Add(string(rune('a'+i)), p)
	}
	s.Build()
	return s
}

func BenchmarkRegexSetBenign(b *testing.B) {
	s := buildBenchSet()
	text := "GET /api/users?page=2&size=20 HTTP/1.1 normal benign traffic"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Match(text)
	}
}

func BenchmarkRegexSetHit(b *testing.B) {
	s := buildBenchSet()
	text := "id=1 union select password from users"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Match(text)
	}
}
