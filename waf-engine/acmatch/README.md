# acmatch

高性能多模式匹配引擎，从 [foxWAF](https://github.com/foxwaf/foxwaf) 核心抽离开源。

`import "github.com/foxwaf/acmatch"`

## 解决什么问题

当你有成百上千条正则规则、而绝大多数流量都不命中任何规则时，逐条跑正则会浪费大量 CPU。

`acmatch` 用 **Aho-Corasick 自动机**先对所有正则里“必然出现的字面量”做一次性多模扫描，**只有字面量命中的那几条正则才会被真正执行**——benign 流量直接走 no-match 快路径，且**零漏检**。

## 特性

- **AC 自动机**：按字节构建（不做 rune 解码），失败指针 BFS 一次成型；root 用稠密数组、其余用稀疏 map，兼顾内存与热路径速度。
- **字面量提取**：基于 `regexp/syntax` AST，只取“任意一次匹配都必然包含”的最长字面量；提不出可靠字面量的正则降级为“每次都查”，保证零漏检。
- **零分配热路径**：匹配结果走 `sync.Pool` 复用。
- **纯标准库**，无第三方依赖。AGPL-3.0。

## 快速开始

### 正则集合预筛（推荐用法）

```go
s := acmatch.NewRegexSet(false) // false = 字面量大小写不敏感
s.Add("sqli", `union\s+select`)
s.Add("path", `/etc/passwd`)
s.Add("cmd",  `(curl|wget)`)    // 无单一字面量 -> 自动归入"每次都查"
s.Build()

s.Match("id=1 UNION   SELECT 2") // -> ["sqli"]
s.Match("hello world")           // -> nil（扫一遍 AC 即判定无命中）

// 最外层快路径开关
if s.MightMatch(reqText) {
    // 仅在可能命中时才进入更重的逐条求值
}
```

### 裸 AC 自动机

```go
tr := acmatch.NewTrie(false)
tr.Add("r1", "select")
tr.Add("r2", "union")
tr.Build()
tr.Match("union select") // -> ["r1","r2"]

// 热路径：用对象池避免分配
set := acmatch.AcquireMatchSet()
tr.MatchInto(text, set)
// ... 用 set ...
acmatch.ReleaseMatchSet(set)
```

### 结构化请求体摊平

```go
acmatch.ExtractJSONStrings([]byte(`{"a":"x","b":["y"]}`)) // ["a","x","b","y"]
acmatch.ExtractXMLStrings([]byte(`<r a="v">t</r>`))       // ["r","a","v","t"]
```

## API

| 类型 / 函数 | 说明 |
|---|---|
| `NewTrie(caseSensitive)` → `Add` / `Build` / `Match` / `MatchInto` | Aho-Corasick 多模匹配 |
| `RequiredLiteral(pattern)` | 提取正则必含的最长字面量 |
| `NewRegexSet(caseSensitive)` → `Add` / `Build` / `Match` / `MightMatch` | AC 预筛 + 正则求值 |
| `NewCache(cap)` → `Compile` | 并发安全正则编译缓存 |
| `Acquire/ReleaseMatchSet` | 匹配结果对象池 |
| `ExtractJSONStrings` / `ExtractXMLStrings` | 结构化体摊平 |

构建后 `Match`/`MatchInto` 并发安全（只读）；`Build` 之后不可再 `Add`。

## 测试

```bash
go test ./...
go test -bench=. -benchmem
```

## License

[AGPL-3.0](./LICENSE)。若将本库集成进闭源或 SaaS 服务对外提供，需依协议开源相应源码。商业授权请联系 foxWAF。
