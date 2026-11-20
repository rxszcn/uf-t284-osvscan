# T284 交付文档：别名组修复信息聚合回填

## 1. 根因

发布卡点在结果构建阶段把同一漏洞的多条公告记录按编号合并成组后，组条目只装配一条
`VulnResult`（键为组代表编号 `group.IDs[0]`，见 `processVulnGroups`）。而修复信息回填
路径 `updateVuln` 旧实现仅在遍历到的漏洞记录 ID **等于组代表编号** 时才写入
`FixedVersion`/`IsFixable`：

```go
if outputVuln, exist := vulnMap[vuln.GetId()]; exist { ... }
```

当编号在前的记录（代表编号，如 CVE）自身没有修复事件、另一条公告（如 GHSA）携带修复
版本 1.4.0 时，该修复事件在终端报告链路被**静默丢弃**：修复列显示占位符 `--`，汇总
`FixableCount.Fixed` 为 0，宣称零漏洞可修复。机器可读报告（`PrintJSONResults`）直接
序列化原始 `VulnerabilityResults`，每条记录的 affected 修复事件原样保留，因此同一
漏洞两种输出一睡一醒。严重度在 `grouper.calculateMaxSeverities` 中按组内跨记录取最高
聚合，而修复列只看单一记录，同一行内自相矛盾。把修复事件挪到编号在前的记录上时，旧
代码恰好命中代表编号，对照组立即正常——与联调现象一致。

## 2. 修复方案与聚合口径

### 2.1 方案

`updateVuln` 先由 `vulnPkg.Groups` 建立"成员记录 ID → 组代表编号"的映射，遍历
`vulnPkg.Vulnerabilities` 时把每条记录的修复计算结果回填到其所属组的唯一条目上，
而不是仅命中代表编号自身的记录。描述信息仍只取自代表编号记录，展示编号与链接口径
不变。

### 2.2 多成员修复版本不一致时的聚合口径：取最高修复版本

- 组内**任一**成员记录对当前安装包携带修复事件，组即为可修复（`IsFixable=true`），
  成员修复版本不丢弃。
- 多条成员修复版本不一致时，组修复版本取**最高**者（按生态前缀的语义化版本比较，
  复用 `semantic` 包，与 `getNextFixVersion`/`calculatePackageFixedVersion` 同一
  比较口径）。

**理由**：发布卡点按公告记录逐条核对修复状态作放行依据。每条记录的"下一修复版本"
语义是"修复该公告所需的最低版本"（`getNextFixVersion` 在记录内取最小修复事件的
既有口径不变）；同一漏洞的不同公告由发布方按自身节奏给出修复版本，只有升级到各
成员修复版本的**最高者**，才能保证每一条成员公告的修复要求都被满足。若取最低者，
升级到该版本后仍有成员公告处于未修复状态，逐条核对时会被卡点拦下，与报告宣称的
"可修复"自相矛盾。包级修复版本（`calculatePackageFixedVersion`）原本就取各漏洞
修复版本的最高者，组内取最高与之同构，语义自洽。

### 2.3 既有行为保持

- 组内成员修复一致（或仅一条记录）时，最高者即该版本本身，既有快照场景读数不变。
- 组内无任何成员携带修复事件时，仍回填占位符（`No fix available`，安装版本不可解析
  时为 `N/A`），vertical 等无条件打印 `FixedVersion` 的输出口径不变。
- 严重度聚合（`grouper.calculateMaxSeverities` 组内取最高）未改动。
- 代表编号选取、别名展示与 OSV 链接生成逻辑未改动。

## 3. 逐文件改动面登记

| 文件 | 改动 | 落地的要求 |
| --- | --- | --- |
| `internal/output/output_result.go` | 重写 `updateVuln`：新增"成员 ID → 组代表编号"映射，组内跨记录聚合回填修复信息；新增 `maxFixVersion` 辅助函数 | 根因修复；组内修复信息按记录聚合回填；成员修复版本不静默丢弃；多成员修复版本冲突取最高的聚合口径；未修复占位符口径保持 |
| `internal/output/output_result_test.go` | 新增 `buildAliasGroupResult`/`onlyRegularVuln` 测试辅助与三个测试函数 | 三类断言用例：`TestBuildResults_AliasGroupFixBackfill`（别名组修复回填）、`TestBuildResults_FixEventPositionContrast`（修复事件位置对照）、`TestBuildResults_ConflictingMemberFixVersions`（多成员修复版本冲突聚合，含记录顺序对照） |

改动面收在结果构建实现及其测试，未触碰 `internal/grouper`（分组与严重度聚合语义
不变，其既有测试原样通过），未触碰展示编号/链接与机器可读报告序列化路径。

要求落点对照：

- 组内修复信息按记录聚合回填 → `updateVuln` 的 `representativeID` 映射与回填循环。
- 成员携带的修复版本不得静默丢弃 → 任一成员 `fixable` 即置组 `IsFixable` 并回填版本。
- 多成员修复版本冲突聚合口径 → `maxFixVersion`（取最高，理由见 2.2）。
- 展示编号与链接保持既有口径 → 未改动 `processVulnGroups` 及各渲染器的 ID/链接逻辑。
- 成员修复一致的既有快照场景行为不变 → 一致时最高者即该版本；`__snapshots__` 全部
  既有快照测试零改动通过。
- 严重度聚合语义不变 → `internal/grouper` 零改动。
- 三类断言用例随修复交付 → `output_result_test.go` 三个测试函数，归属既有输出测试
  文件与 `go test` 框架。
- 既有测试保持通过 → 见第 4 节验收读数。

## 4. 验收命令最终读数

```
$ go test -count=1 ./internal/output/... ./internal/grouper/...
ok  	github.com/google/osv-scanner/v2/internal/output	0.347s
?   	github.com/google/osv-scanner/v2/internal/output/sbom	[no test files]
ok  	github.com/google/osv-scanner/v2/internal/grouper	1.792s
```

零失败。新增用例单独读数：

```
--- PASS: TestBuildResults_AliasGroupFixBackfill (0.00s)
--- PASS: TestBuildResults_FixEventPositionContrast (0.00s)
--- PASS: TestBuildResults_ConflictingMemberFixVersions (0.00s)
```

## 5. 构造输入实测读数

构造输入（快照环境内零外部依赖自建，临时脚手架运行后即删除）：npm 包 `mine1@1.2.3`，
别名组两条记录——编号在前的 `CVE-2025-0001`（组代表编号，自身无修复事件）与
`GHSA-aaaa-bbbb-cccc`（别名指向该 CVE，携带修复事件 `fixed=1.4.0`），分组经
`grouper.Build` 按扫描器同路径构建。每轮读取终端表格报告该组行的 Fixed Version 列
与机器可读 JSON 报告该组记录 affected 中的修复版本，重复 10 轮。

修复前对照读数（缺陷复现）：

```
第01轮 终端修复列=--（占位符，行：| https://osv.dev/CVE-2025-0001 | | npm | mine1 | 1.2.3 | -- | package-lock.json |） 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第02轮 同上
第03轮 同上
```

修复后 10 轮实测读数：

```
第01轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第02轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第03轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第04轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第05轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第06轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第07轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第08轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第09轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
第10轮 终端修复列=1.4.0 机器可读修复说明=GHSA-aaaa-bbbb-cccc->1.4.0
```

10 轮读数一致：终端修复列与机器可读修复说明对同一组均读出 1.4.0，两种输出对齐。
