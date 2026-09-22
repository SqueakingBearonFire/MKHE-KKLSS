# MK-BFV 两方加权点积（d·w）实测分析报告

> 场景：P1 持有 d1..d5（每列 100,000 条 int64），P2 持有 w1..w5（各 1 条 int64），双方数据均私有。
> 计算 `res[i] = Σk dk[i]·wk`，结果仅交付 P1。
> 基准代码：`mkbfv/dotproduct_test.go`；测试机：Windows 10，8 GB 内存，Go 1.23。

---

## 一、代码结构分析

```
MKHE-KKLSS (Go module: mk-lattigo, 依赖 Lattigo v2.3.0)
├── mkrlwe/   多密钥 RLWE 底层：密钥/CRS/keyswitch(含 hoisted)/快速基扩展
│   ├── elements.go   密文 = map[partyID]*Poly + "0"，p 方密文含 p+1 个 Q 域多项式
│   ├── decryptor.go  PartialDecrypt: 原地去掉本方分量（阈值解密原语）
│   ├── keyswitch.go  分解 / 外积 / MulAndRelin / Rotate / Conjugate
│   └── params.go     NewParameters 同时生成 ~19 个 CRS（公共随机数，可由种子导出）
├── mkbfv/    MK-BFV：params / keys / keygen / encryptor / decryptor / evaluator
│   ├── keygen.go     GenRelinearizationKey（gadget 分解含 T 因子）
│   ├── keyswitch.go  MulAndRelinBFV：显式支持两操作数属于不同参与方的交叉项
│   └── evaluator.go  AddNew / SubNew / MulRelinNew(重线性化内置) / RotateNew
├── mkckks/   MK-CKKS（含 Rescale、明文-密文乘 MulPtxtNew）
├── cnn/      MNIST CNN 端到端基准（基于 MK-CKKS；cnn_test.go:195 存在既有编译错误）
├── dotproduct/  CSV 端到端 CLI + 测试数据（本场景新增）
├── Dockerfile    Linux 最优性能测试镜像（本场景新增）
└── doc/      本报告
```

与本场景直接相关的关键机制：

| 机制 | 位置 | 说明 |
|---|---|---|
| 密文结构 | mkrlwe/elements.go:17 | 2 方联合密文 = "0" + P1 + P2 共 3 个多项式 |
| 跨方乘法 | mkbfv/keyswitch.go:115 | idset0/idset1 不相交的交叉项（202-216 行），relin 融合 |
| 阈值解密 | mkrlwe/decryptor.go:26 | 依次 PartialDecrypt；最后解密者之外的所有方都看不到明文 |
| SIMD 批处理 | lattigo bfv Encoder | 每 slot 一个系数；密文乘 = 明文逐元素乘；要求 T ≡ 1 (mod 2N) |
| relin key | mkbfv/keygen.go:24 | 每方 6 个 SwitchingKey（b、d、v 三元组 ×2），与 T 相关 |

注意：mkbfv 不提供明文-密文乘法（只有 mkckks 有 MulPtxtNew），因此 P2 的权重必须加密成密文参与 ct-ct 乘法。

## 二、协议设计

```
① 一次性设置：各方 GenKeyPair + GenRelinearizationKey → 广播 pk + rlk
② P1：d1..d5 按 slot 打包，每列 ⌈100000/N⌉ 个密文，用 P1 公钥加密 → 上传求值方
③ P2：每个 wk 广播到全部 N 个 slot，各加密成 1 个密文（共 5 个）→ 上传求值方
④ 求值方：对每批 j 计算 res[j] = Σk MulRelinNew(Dk[j], Wk)，联合密钥 {P1,P2} 下
⑤ 解密：P2 先 PartialDecrypt（P1 分量仍在 → P2 对结果盲）
        → P1 PartialDecrypt + 解码，100,000 条结果仅 P1 获得
```

## 三、int64 表示约束（实测确认）

1. `ParametersLiteral.T` 为 uint64，lattigo 要求 **T ≤ Q[0]**（bfv/params.go:126）且 **T ≡ 1 (mod 2N)** → T 上限约 2^53；
2. 全范围 int64 乘积之和可达 5·2^126 ≈ 2^129，单素数明文模数无法直接表示；
3. 实测：pn14（Q=319 bit）在 **T ≈ 2^53、|d|,|w| ≤ 2^24** 时 100,000 条结果全部正确 —— 当前瓶颈是库的 T ≤ Q[0] 结构限制，而非同态噪声（余量充足）。

**全范围 int64 方案**：将输入按 CRT 拆成 3 个 < 2^53 的份额，3 组密文并行计算后 CRT 重构；耗时与通信量按 ×3 估算即可。

## 四、实测数据

### 配置 A：pn14（N=16384，logQP=439，T≈2^53，slots/ct=16384 → 每列 7 个密文）

| 阶段 | 耗时 | 通信量 | 备注 |
|---|---|---|---|
| 0 参数+CRS 生成 | 2.2 s | 0 | 本地生成，种子可推导 |
| 1 双方密钥生成 | 0.33 s | 38 MiB/方，共 76 MiB | 一次性（pk 2 MiB + rlk 36 MiB/方） |
| 2 P1 编码+加密 35 ct | 0.33 s | 52.5 MiB（P1→E） | |
| 3 P2 编码+加密 5 ct | 0.06 s | 7.5 MiB（P2→E） | |
| 4 求值：35 MulRelin + 28 Add | **5.98 s** | 0 | mul 169.7 ms/次，add 1.5 ms/次 |
| 5 E→P1 结果 7 ct ×3 poly | — | 15.75 MiB | |
| 5a P2 部分解密 | 0.03 s | 15.75 MiB（P1→P2） | |
| 5b P1 部分解密 | 0.03 s | 10.5 MiB（P2→P1） | |
| 5c P1 解码 | 0.01 s | — | |
| **在线合计** | **6.44 s** | **102 MiB**（外部求值方）/ 33.75 MiB（P1 兼任求值方） | 摊销 1069.5 B/记录 |

正确性：0 / 100,000 错误。

### 配置 B：pn15（自定义 10-limb Q=540 bit，logQP=660，T≈2^53，slots/ct=32768 → 每列 4 个密文）

运行环境：GOGC=40 GOMEMLIMIT=6GiB，常驻内存 ~4.5 GB（自 PN15QP880 裁剪，原参数 CRS 需 >5 GB 不适配本机）。

| 阶段 | 耗时 | 通信量 |
|---|---|---|
| 0 参数+CRS 生成 | 25.1 s | 0 |
| 1 双方密钥生成 | 5.4 s | 186 MiB/方，共 372 MiB |
| 2 P1 编码+加密 20 ct | 1.4 s | 100 MiB（P1→E） |
| 3 P2 编码+加密 5 ct | 0.27 s | 25 MiB（P2→E） |
| 4 求值：20 MulRelin + 16 Add | **28.3 s**（1.41 s/次） | 0 |
| 5 解密+解码（含传输 30/30/20 MiB） | 0.2 s | 80 MiB |
| **在线合计** | **30.1 s** | **205 MiB**（外部求值方） |

正确性：0 / 100,000 错误。

## 五、瓶颈分析与结论

1. **求值阶段占在线时间 ~93%，其中 MulRelin 占 99%**。每次两方 MulRelin 包含：
   2 次 DecomposeBFV（R=Q·QMul 域）+ 4 次外积（keyswitch.go:230-250 中 idset0 一方需 3 次）+ R 域张量积 + Quantize 基扩展。加解密/编码合计不到 0.5 s。
2. **本负载下 pn14 全面优于 pn15**（6.4 s vs 30.1 s；102 vs 205 MiB）：密文数多 75%，但单次操作在 N=2^15、10-limb 下贵 8 倍（另有 ~4 GB 活跃堆的 GC 压力），大 N 的 slot 摊销在 10 万条规模无法兑现。
3. **通信放大约 27×**（1069 B/记录 vs 明文 40 B/记录）。一次性 rlk 达 36 MiB/方（pn14）——gamma=2、alpha=1 导致 beta=QCount，分解粒度过细是 relin key 庞大的根因。
4. **可优化方向**：
   - 权重密文 Wk 被复用 ctsPerCol 次，但 MulRelinNew 每次都对两个操作数重新分解；预分解/hoist 复用可省约一半分解开销（需扩展 API，rlkSet.HoistPool 目前为每次调用共享的内部池）；
   - 54-bit limb 位打包（bit-packing）可省约 20% 通信；
   - 全 int64 需 CRT ×3；
   - 第三方求值方场景下，P2 上传与 P1 数据加密可流水线并行，端到端时间趋近于求值时间。

## 六、工具链与复现方法

代码组织（本场景新增部分）：

```
mkbfv/dotproduct.go        协议库：RunDotProduct / DotProductStats / FindPrimeT / MinT /
                           MaxT，参数字面量 PN14QP439、PN15QP660（10-limb 裁剪版）
mkbfv/dotproduct_test.go   库级基准（go test），随机数据
dotproduct/main.go         CSV 端到端 CLI：两方 CSV 输入 -> 结果 CSV，支持 -gen 生成数据
dotproduct/data/           p1_data.csv (100000x5), p2_weights.csv (1x5), res.csv (输出)
Dockerfile / .dockerignore Linux 高配机器上跑最优性能
```

CSV 约定：P1 文件首行表头 `d1..dK`，之后每记录一行 int64；P2 文件表头 `w1..wK` 加单行；输出为单列 `res`。K（列数）任意，明文模数 T 按数据实际范围自动推导（要求 `2·K·maxD·maxW < T ≤ Q[0]`，超界报错并提示 CRT 拆分）。

本地运行：

```bash
# 生成确定性测试数据（默认 10 万行、|d|,|w| < 2^20）
go run ./dotproduct -gen

# 端到端：读 CSV -> 协议 -> 校验 -> 写 res.csv
go run ./dotproduct -p1 data/p1_data.csv -p2 data/p2_weights.csv -out data/res.csv

# 大参数集（需 ~4.5 GB 内存）
GOGC=400 go run ./dotproduct -conf pn15 -p1 data/p1_data.csv -p2 data/p2_weights.csv -out data/res.csv

# 库级基准（与本报告数据同源）
go test ./mkbfv -run TestMKBFVDotProduct -v -timeout 30m -args -dotconf=pn14
GOGC=400 go test ./mkbfv -run TestMKBFVDotProduct -v -timeout 30m -args -dotconf=pn15
# 可调：-dottmin（T 下界）、-dotbound（|d|,|w| 界）
```

Docker（推荐在 Linux 高配机器上测最优性能；本报告数据来自 8 GB 内存的低配机，pn15 数字明显受 GC 拖累）。镜像不自动执行任何命令，`docker run -it` 进入 /app 下的 shell（dotproduct 已装进 PATH，CSV 数据在 dotproduct/data/，Go 工具链可用），命令手动执行：

```bash
docker build -t mkhe-dotproduct .

# 进入容器（pn14 场景 ~1.5 GB 内存即可；挂载 logs 目录保存测试日志）
mkdir -p logs && docker run -it --rm -v "$PWD/logs":/logs mkhe-dotproduct

# pn15 场景建议给足内存并在启动时调 GC（32 GB 机器可用 GOGC=200..400）
docker run -it --rm -m 12g -e GOGC=200 -v "$PWD/logs":/logs mkhe-dotproduct
```

容器内（位于 /app，模块根目录）：

```bash
# ===== 三个计算场景（-conf 默认 all = pn14 + pn15 依次执行）=====
cd /app/dotproduct   # 默认相对路径 data/... 在此目录下生效

# 场景 1：加权点积 res[i] = Σk dk[i]·wk（P2 持 5 个标量；镜像内置数据直接可用）
dotproduct -scenario 1 -reps 3 2>&1 | tee /logs/s1.log

# 场景 2：逐行加权点积 res[i] = Σk dk[i]·wk[i]（P2 持 5 列 × 10 万行，先确定性生成）
dotproduct -gen -scenario 2 -gendir data/s2
dotproduct -scenario 2 -p1 data/s2/p1_data.csv -p2 data/s2/p2_data.csv -reps 3 2>&1 | tee /logs/s2.log

# 场景 3：res[i] = (d1+w1)·…·(d5+w5)（深度 3 乘法树；默认 bound=512 保证 T ≤ Q[0]）
dotproduct -gen -scenario 3 -gendir data/s3
dotproduct -scenario 3 -p1 data/s3/p1_data.csv -p2 data/s3/p2_data.csv -reps 3 2>&1 | tee /logs/s3.log

# 指定单个参数集 / 生成其他规模数据
dotproduct -scenario 1 -conf pn15 -reps 3
dotproduct -gen -scenario 3 -gendir data/s3big -rows 1000000 -bound 512

# 库级基准（场景 1，与本报告表格数据同源）
go test ./mkbfv -run TestMKBFVDotProduct -v -timeout 30m -args -dotconf=pn14
GOGC=400 go test ./mkbfv -run TestMKBFVDotProduct -v -timeout 30m -args -dotconf=pn15
```

三场景说明（协议实现 `mkbfv/scenarios.go`）：

| 场景 | P2 输入 | 计算 | 求值电路（每批 j） |
|---|---|---|---|
| 1 | w1..w5 各 1 条 | res[i] = Σk dk[i]·wk | K 次 MulRelin + K-1 次 Add |
| 2 | w1..w5 各 10 万条 | res[i] = Σk dk[i]·wk[i] | 同上（W 换为逐批密文） |
| 3 | w1..w5 各 10 万条 | res[i] = Πk (dk[i]+wk[i]) | K 次跨方 Add + K-1 次平衡两两 MulRelin（深度 ⌈log2 K⌉） |

结果自动写入 `data/res_s<场景>_<参数集>.csv`；T 按数据范围自动推导（场景 3 用
`MinTSumProduct = 4·(maxD+maxW)^K`，K=5、bound=512 时 T≈2^52 ≤ Q[0]≈2^53）。

挂载宿主机目录交换数据：`docker run -it --rm -v $PWD/data:/data mkhe-dotproduct`，容器内用 `/data/p1_data.csv` 等路径。

GC 调优：pn14 活跃堆 ~1 GB（默认 GOGC 即可，200-400 略有提升）；pn15 活跃堆 ~4.5 GB（32 GB 机器建议 `GOGC=200..400`，16 GB 机器保持默认并加 `GOMEMLIMIT=12GiB`，可在容器内 export 或 docker run -e 传入）。纯 Go 无 cgo，性能主要取决于单核主频与内存带宽。
