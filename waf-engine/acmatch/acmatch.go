// Package acmatch 是一个高性能多模式匹配引擎，从 foxWAF 核心中抽离开源。
//
// 它解决的核心问题：当你有成百上千条正则规则、而绝大多数请求都不命中任何
// 规则时，逐条跑正则会浪费大量 CPU。acmatch 用 Aho-Corasick 自动机先对所有
// 正则里“必然出现的字面量”做一次性多模扫描，只有字面量命中的那几条正则才会
// 被真正执行——benign 流量直接走 no-match 快路径，零漏检。
//
// 设计要点：
//   - AC 自动机按字节构建（不做 rune 解码），失败指针 BFS 一次成型，root 节点
//     用稠密数组、其余节点用稀疏 map，兼顾内存与热路径速度。
//   - 字面量提取基于 regexp/syntax AST，只取“任意一次匹配都必然包含”的最长
//     字面量；提不出可靠字面量的正则降级为“每次都查”，保证零漏检。
//   - 匹配结果走 sync.Pool 复用，热路径尽量零分配。
//   - 仅依赖 Go 标准库，无第三方依赖。
//
// 单文件结构（按 section 顺序）：
//  1. AC 自动机：节点与构建
//  2. AC 自动机：匹配
//  3. 匹配结果对象池
//  4. 正则字面量提取
//  5. 正则编译 LRU 缓存
//  6. 正则集合预筛（AC + 正则）
//  7. JSON / XML 取值辅助
//
// 本文件以 AGPL-3.0 授权，详见同目录 LICENSE。
package acmatch

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// =============================================================================
// 1. AC 自动机：节点与构建
// =============================================================================

// acNode 是 Aho-Corasick trie 的一个节点。
//
// 非 root 节点用稀疏 map 存子节点（多数节点只有少量分支，避免每节点 256 指针的
// 内存浪费）；root 节点额外用稠密数组（见 Trie.dense），因为 root 的子节点查询
// 在匹配热路径上每个输入字节都会触发一次。
type acNode struct {
	children map[byte]*acNode
	fail     *acNode
	// out 是“以本节点结尾”的模式 ID 列表。
	out []string
	// dictLink 指向沿失败链最近的一个终结节点（字典后缀链），用于匹配时 O(命中数)
	// 地收集所有重叠命中，避免每个字节都回溯整条失败链。
	dictLink *acNode
}

// Trie 是一个 Aho-Corasick 多模式自动机。
//
// 用法：NewTrie -> 多次 Add -> Build -> 多次 Match/MatchInto。
// Build 之后不可再 Add。Match/MatchInto 并发安全（只读）。
type Trie struct {
	root          *acNode
	dense         [256]*acNode // root 的稠密子节点索引
	caseSensitive bool
	built         bool
	patternCount  int
}

// NewTrie 创建自动机。caseSensitive=false 时大小写不敏感（按 ASCII 折叠为小写，
// 模式与输入都会被小写化）。
func NewTrie(caseSensitive bool) *Trie {
	return &Trie{
		root:          &acNode{children: make(map[byte]*acNode)},
		caseSensitive: caseSensitive,
	}
}

// PatternCount 返回已加入的模式数量。
func (t *Trie) PatternCount() int { return t.patternCount }

// Add 加入一个模式串，命中时 Match 会返回对应的 id。
// 同一字面量可对应多个 id（例如多条规则共用一个字面量）。空模式被忽略。
// 必须在 Build 之前调用。
func (t *Trie) Add(id, pattern string) {
	if t.built || pattern == "" {
		return
	}
	if !t.caseSensitive {
		pattern = asciiLower(pattern)
	}
	cur := t.root
	for i := 0; i < len(pattern); i++ {
		b := pattern[i]
		next := cur.children[b]
		if next == nil {
			next = &acNode{children: make(map[byte]*acNode)}
			cur.children[b] = next
		}
		cur = next
	}
	cur.out = append(cur.out, id)
	t.patternCount++
}

// Build 计算失败指针与字典后缀链，并稠密化 root。BFS 一次成型。
// 重复调用是安全的空操作。
func (t *Trie) Build() {
	if t.built {
		return
	}
	// root 的直接子节点失败指针指向 root；其余 BFS 计算。
	queue := make([]*acNode, 0, 64)
	for b := 0; b < 256; b++ {
		child := t.root.children[byte(b)]
		if child == nil {
			continue
		}
		child.fail = t.root
		t.dense[b] = child
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for b, child := range cur.children {
			// 沿父节点的失败链找 b 的转移，作为 child 的失败指针。
			f := cur.fail
			for f != nil && f.children[b] == nil {
				f = f.fail
			}
			if f == nil {
				child.fail = t.root
			} else {
				child.fail = f.children[b]
			}
			// 字典后缀链：失败目标若是终结节点则直接指它，否则继承其 dictLink。
			if len(child.fail.out) > 0 {
				child.dictLink = child.fail
			} else {
				child.dictLink = child.fail.dictLink
			}
			queue = append(queue, child)
		}
	}
	t.built = true
}

// =============================================================================
// 2. AC 自动机：匹配
// =============================================================================

// Match 扫描 text，返回所有命中模式的 id（去重，顺序不保证）。
// 未命中返回 nil。Build 之后并发安全。
func (t *Trie) Match(text string) []string {
	seen := make(map[string]struct{})
	t.MatchInto(text, seen)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// MatchInto 扫描 text，把命中的模式 id 写入调用方提供的 out 集合（去重）。
// 适合热路径：配合 sync.Pool 复用 out，可做到近零分配。
func (t *Trie) MatchInto(text string, out map[string]struct{}) {
	if !t.built {
		t.Build()
	}
	cur := t.root
	for i := 0; i < len(text); i++ {
		b := text[i]
		if !t.caseSensitive {
			b = lowerByte(b)
		}
		// 沿失败链找到能接受 b 的节点。
		for cur != t.root && cur.children[b] == nil {
			cur = cur.fail
		}
		var next *acNode
		if cur == t.root {
			next = t.dense[b] // root 走稠密索引
		} else {
			next = cur.children[b]
		}
		if next == nil {
			continue // 仍停在 root
		}
		cur = next
		// 收集当前节点及其字典后缀链上的所有命中。
		if len(cur.out) > 0 {
			for _, id := range cur.out {
				out[id] = struct{}{}
			}
		}
		for d := cur.dictLink; d != nil; d = d.dictLink {
			for _, id := range d.out {
				out[id] = struct{}{}
			}
		}
	}
}

// =============================================================================
// 3. 匹配结果对象池
// =============================================================================

var matchSetPool = sync.Pool{
	New: func() any { return make(map[string]struct{}, 32) },
}

// AcquireMatchSet 从池中取一个空集合，配合 MatchInto 使用。
func AcquireMatchSet() map[string]struct{} {
	return matchSetPool.Get().(map[string]struct{})
}

// ReleaseMatchSet 清空并归还集合。归还后不得再使用该 map。
func ReleaseMatchSet(m map[string]struct{}) {
	for k := range m {
		delete(m, k)
	}
	matchSetPool.Put(m)
}

// =============================================================================
// 4. 正则字面量提取
// =============================================================================

// minLiteralLen 是可用于预筛的最短字面量长度；过短的字面量区分度太低、
// 反而会让预筛形同虚设，因此低于此长度视为“无可用字面量”。
const minLiteralLen = 3

// RequiredLiteral 返回“任意一次成功匹配都必然包含”的最长字面量子串。
//
// 例如 `select\s+.*from` -> "select"（"from" 也必含，取较长者）；
// `(abc|def)` -> ""（无单一必含字面量）；`(?i)union` -> ""（大小写折叠，
// 字面量不可靠，降级为每次都查以保证零漏检）。
// 无法保证任何必含字面量时返回 ""。
func RequiredLiteral(pattern string) string {
	return requiredLiteral(pattern, false)
}

// requiredLiteral 是 RequiredLiteral 的内部实现。fold=true 时按大小写不敏感处理：
// 接受大小写折叠的字面量并统一小写化返回（供大小写不敏感的预筛 trie 使用）。
func requiredLiteral(pattern string, fold bool) string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return ""
	}
	lit := longestRequiredLiteral(re.Simplify(), fold)
	if len(lit) < minLiteralLen {
		return ""
	}
	if fold {
		lit = asciiLower(lit)
	}
	return lit
}

// longestRequiredLiteral 递归遍历正则 AST，返回必含的最长字面量。
// 遇到可选/或/星号等无法保证出现的结构时跳过它们。
// fold=false 时遇到大小写折叠字面量直接放弃（大小写敏感预筛不可靠）；
// fold=true 时折叠字面量可用（调用方会统一小写化并配大小写不敏感 trie）。
func longestRequiredLiteral(re *syntax.Regexp, fold bool) string {
	usableLiteral := func(r *syntax.Regexp) bool {
		return r.Op == syntax.OpLiteral && (fold || r.Flags&syntax.FoldCase == 0)
	}
	switch re.Op {
	case syntax.OpLiteral:
		if !fold && re.Flags&syntax.FoldCase != 0 {
			return "" // 大小写折叠，字面量不可直接用于大小写敏感预筛
		}
		return string(re.Rune)

	case syntax.OpConcat:
		// 累积连续字面量片段，遇到非字面量子表达式则断开并尝试其内部必含字面量。
		best, cur := "", ""
		for _, sub := range re.Sub {
			if usableLiteral(sub) {
				cur += string(sub.Rune)
				continue
			}
			if len(cur) > len(best) {
				best = cur
			}
			cur = ""
			if l := longestRequiredLiteral(sub, fold); len(l) > len(best) {
				best = l
			}
		}
		if len(cur) > len(best) {
			best = cur
		}
		return best

	case syntax.OpCapture, syntax.OpPlus:
		// 捕获组透明；x+ 至少出现一次，内部字面量必含。
		return longestRequiredLiteral(re.Sub[0], fold)

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return longestRequiredLiteral(re.Sub[0], fold)
		}
		return ""

	default:
		// OpAlternate / OpStar / OpQuest / OpAnyChar / OpCharClass 等无法保证。
		return ""
	}
}

// =============================================================================
// 5. 正则编译 LRU 缓存
// =============================================================================

// Cache 是一个带容量上限的并发安全正则编译缓存（LRU 近似：满了直接清空重建，
// 实现简单且对编译型负载足够——正则集合通常远小于容量）。
type Cache struct {
	mu       sync.RWMutex
	capacity int
	m        map[string]*regexp.Regexp
}

// NewCache 创建缓存，capacity<=0 时取默认 256。
func NewCache(capacity int) *Cache {
	if capacity <= 0 {
		capacity = 256
	}
	return &Cache{capacity: capacity, m: make(map[string]*regexp.Regexp, capacity)}
}

// Compile 返回（缓存的）已编译正则。线程安全。
func (c *Cache) Compile(pattern string) (*regexp.Regexp, error) {
	c.mu.RLock()
	if re, ok := c.m[pattern]; ok {
		c.mu.RUnlock()
		return re, nil
	}
	c.mu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.m) >= c.capacity {
		c.m = make(map[string]*regexp.Regexp, c.capacity)
	}
	c.m[pattern] = re
	c.mu.Unlock()
	return re, nil
}

// =============================================================================
// 6. 正则集合预筛（AC + 正则）
// =============================================================================

// RegexSet 把一批带 id 的正则组织起来，用 AC 自动机对“必含字面量”做预筛，
// 只对字面量命中的正则真正求值。无可用字面量的正则进入 always 列表、每次都查。
// 这正是 foxWAF benign 流量 no-match 快路径的来源：大多数请求扫一遍 AC 即可
// 判定“无任何规则可能命中”，而不必逐条跑正则。
//
// 用法：New -> 多次 Add -> Build -> 多次 Match。Build 之后不可再 Add。
type RegexSet struct {
	caseSensitive bool
	trie          *Trie
	byID          map[string]*regexp.Regexp
	always        []reEntry // 无可用字面量，每次都查
	built         bool
}

type reEntry struct {
	id string
	re *regexp.Regexp
}

// NewRegexSet 创建集合。caseSensitive 控制字面量预筛是否大小写敏感
// （正则本身的大小写由其自身 flag 决定，如内嵌 (?i)）。
func NewRegexSet(caseSensitive bool) *RegexSet {
	return &RegexSet{
		caseSensitive: caseSensitive,
		trie:          NewTrie(caseSensitive),
		byID:          make(map[string]*regexp.Regexp),
	}
}

// Add 加入一条正则。id 由调用方定义、命中时原样返回；同一 id 可多次加入不同正则。
// 返回正则编译错误。必须在 Build 之前调用。
func (s *RegexSet) Add(id, pattern string) error {
	if s.built {
		return nil
	}
	// 大小写不敏感模式下，正则本身也按 (?i) 编译，确保它与字面量预筛口径一致：
	// 否则预筛会因小写命中而把大写输入选为候选，正则却因大小写敏感而漏判。
	compilePat := pattern
	if !s.caseSensitive {
		compilePat = "(?i)" + pattern
	}
	re, err := regexp.Compile(compilePat)
	if err != nil {
		return err
	}
	s.byID[id] = re
	if lit := requiredLiteral(pattern, !s.caseSensitive); lit != "" {
		// 字面量进 trie；大小写不敏感时 requiredLiteral 已折叠小写、Trie 亦小写化输入。
		s.trie.Add(id, lit)
	} else {
		s.always = append(s.always, reEntry{id: id, re: re})
	}
	return nil
}

// Build 构建预筛自动机。重复调用是安全的空操作。
func (s *RegexSet) Build() {
	if s.built {
		return
	}
	s.trie.Build()
	s.built = true
}

// Match 返回所有真正命中 text 的正则 id（去重，顺序不保证）。
// 流程：AC 预筛出字面量命中的候选 -> 逐个跑正则确认 -> 并上 always 列表的结果。
func (s *RegexSet) Match(text string) []string {
	if !s.built {
		s.Build()
	}
	result := make(map[string]struct{})

	// 预筛候选：字面量命中者才跑正则。
	cand := AcquireMatchSet()
	s.trie.MatchInto(text, cand)
	for id := range cand {
		if re := s.byID[id]; re != nil && re.MatchString(text) {
			result[id] = struct{}{}
		}
	}
	ReleaseMatchSet(cand)

	// 无字面量、必须每次都查的正则。
	for _, e := range s.always {
		if e.re.MatchString(text) {
			result[e.id] = struct{}{}
		}
	}

	if len(result) == 0 {
		return nil
	}
	out := make([]string, 0, len(result))
	for id := range result {
		out = append(out, id)
	}
	return out
}

// MightMatch 仅做 AC 预筛：返回 true 表示“可能有正则命中、需进一步求值”，
// 返回 false 表示“确定没有任何带字面量的正则会命中”。它不考虑 always 列表，
// 适合作为最外层的快路径开关（always 列表为空时即为精确判定）。
func (s *RegexSet) MightMatch(text string) bool {
	if !s.built {
		s.Build()
	}
	if len(s.always) > 0 {
		return true
	}
	cand := AcquireMatchSet()
	s.trie.MatchInto(text, cand)
	hit := len(cand) > 0
	ReleaseMatchSet(cand)
	return hit
}

// =============================================================================
// 7. JSON / XML 取值辅助
// =============================================================================

// ExtractJSONStrings 递归提取 JSON 文档中的所有字符串值与对象键。
// 用于把结构化请求体摊平成可供 Match 扫描的文本片段。解析失败返回 nil。
func ExtractJSONStrings(data []byte) []string {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	var out []string
	walkJSON(v, &out)
	return out
}

func walkJSON(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case map[string]any:
		for k, sub := range t {
			*out = append(*out, k)
			walkJSON(sub, out)
		}
	case []any:
		for _, sub := range t {
			walkJSON(sub, out)
		}
	}
}

// ExtractXMLStrings 提取 XML 中的元素名、属性名、属性值与文本节点。
// 解析失败时返回已提取到的部分。
func ExtractXMLStrings(data []byte) []string {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			out = append(out, t.Name.Local)
			for _, a := range t.Attr {
				out = append(out, a.Name.Local, a.Value)
			}
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// =============================================================================
// 工具
// =============================================================================

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func asciiLower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := range b {
		b[i] = lowerByte(b[i])
	}
	return string(b)
}
