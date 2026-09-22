// Command gencharts renders the SVG figures embedded in doc/benchmark-report.md
// from the measured benchmark data of the two-party MK-BFV weighted-sum
// protocol (mkbfv/dotproduct_test.go and the dotproduct CLI, run on the
// 8 GB / Windows 10 / Go 1.23 reference machine). Edit the constants below
// and re-run from the module root to refresh the figures:
//
//	go run ./doc/gencharts   (writes doc/charts/*.svg)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const font = ` font-family="Segoe UI, Microsoft YaHei, Arial, sans-serif"`

const (
	blueDark  = "#2E75B6"
	blueMid   = "#4472C4"
	blueLight = "#9DC3E6"
	pkBlue    = "#BDD7EE"
	orange    = "#ED7D31"
	orangeLt  = "#F8CBAD"
	green     = "#70AD47"
	greenLt   = "#A9D18E"
	gray      = "#A6A6A6"
	txtDark   = "#1F1F1F"
	txtMid    = "#404040"
	txtGray   = "#595959"
)

func text(x, y int, anchor string, size int, weight, fill, s string) string {
	w := ""
	if weight != "" {
		w = ` font-weight="` + weight + `"`
	}
	return fmt.Sprintf(`<text x="%d" y="%d" text-anchor="%s" font-size="%d"%s fill="%s"%s>%s</text>`,
		x, y, anchor, size, w, fill, font, s)
}

func rect(x, y, w, h int, fill string) string {
	return fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" fill="%s"/>`, x, y, w, h, fill)
}

// strWidth estimates the rendered width of s at the given font size (CJK
// glyphs ~1em, others ~0.55em); used only to lay out the fig2 legend.
func strWidth(s string, size int) float64 {
	w := 0.0
	for _, r := range s {
		if r > 0x2E80 {
			w += float64(size)
		} else {
			w += float64(size) * 0.55
		}
	}
	return w
}

func save(name string, w, h int, body string) {
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`+"\n"+
		`<rect width="100%%" height="100%%" fill="#FFFFFF"/>`+"\n%s\n</svg>\n", w, h, w, h, body)
	if err := os.MkdirAll("doc/charts", 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join("doc/charts", name), []byte(svg), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", filepath.Join("doc", "charts", name))
}

// ---------------- fig 1: per-phase online time ----------------

func figPhaseTime() {
	const W, H = 800, 364
	const plotX, plotW = 220, 470
	const maxV = 28.3

	rows := []struct {
		label  string
		a, b   float64
		la, lb string
	}{
		{"P1 编码+加密（35 / 20 ct）", 0.33, 1.40, "0.33 s", "1.40 s"},
		{"P2 编码+加密（5 ct）", 0.06, 0.27, "0.06 s", "0.27 s"},
		{"同态求值（35 / 20 次 MulRelin）", 5.98, 28.30, "5.98 s", "28.30 s"},
		{"部分解密 + 解码", 0.07, 0.20, "0.07 s", "0.20 s"},
	}

	var b strings.Builder
	b.WriteString(text(W/2, 26, "middle", 16, "bold", txtDark, "图 1：在线各阶段耗时（100,000 条记录）"))
	b.WriteString(text(W/2, 46, "middle", 12, "", txtGray,
		"在线合计：pn14 = 6.44 s，pn15QP660 = 30.1 s（Windows 10 / 8 GB / Go 1.23 参考机实测）"))
	b.WriteString(rect(plotX, 58, 14, 14, blueMid))
	b.WriteString(text(plotX+20, 69, "start", 12, "", txtMid, "pn14（N=2^14）"))
	b.WriteString(rect(plotX+170, 58, 14, 14, orange))
	b.WriteString(text(plotX+190, 69, "start", 12, "", txtMid, "pn15QP660（N=2^15）"))

	y := 92
	for _, r := range rows {
		b.WriteString(text(plotX-12, y+24, "end", 13, "", txtMid, r.label))
		for i := 0; i < 2; i++ {
			v, col, lab := r.a, blueMid, r.la
			if i == 1 {
				v, col, lab = r.b, orange, r.lb
			}
			by := y + i*22
			bw := int(v / maxV * float64(plotW))
			if bw < 2 {
				bw = 2
			}
			b.WriteString(rect(plotX, by, bw, 18, col))
			b.WriteString(text(plotX+bw+6, by+14, "start", 12, "", txtMid, lab))
		}
		y += 64
	}
	b.WriteString(text(W/2, 348, "middle", 12, "", txtGray,
		"同态求值占在线时间：pn14 93%、pn15QP660 94%；其中 MulRelin 占求值时间 99% 以上（Add 仅 1.5 ms/次）"))
	save("fig1-phase-time.svg", W, H, b.String())
}

// ---------------- fig 2: communication breakdown ----------------

func figComm() {
	const W, H = 800, 318
	const plotX, plotW = 220, 470
	const maxV = 372.0

	type seg struct {
		v  float64
		ci int
	}
	rows := []struct {
		label string
		segs  []seg
		total string
	}{
		{"pn14 一次性 setup", []seg{{4, 0}, {72, 1}}, "76 MiB"},
		{"pn14 在线（每次）", []seg{{52.5, 2}, {7.5, 3}, {15.75, 4}, {26.25, 5}}, "102 MiB"},
		{"pn15QP660 一次性 setup", []seg{{12, 0}, {360, 1}}, "372 MiB"},
		{"pn15QP660 在线（每次）", []seg{{100, 2}, {25, 3}, {30, 4}, {50, 5}}, "205 MiB"},
	}
	names := []string{"pk 广播", "rlk 广播", "P1 数据密文", "P2 权重密文", "结果密文分发", "部分解密往返"}
	colors := []string{pkBlue, blueDark, green, greenLt, orange, orangeLt}

	var b strings.Builder
	b.WriteString(text(W/2, 26, "middle", 16, "bold", txtDark, "图 2：通信量构成（MiB，精确 RNS 序列化口径）"))
	b.WriteString(text(W/2, 46, "middle", 12, "", txtGray,
		"外部求值方口径 ｜ pk / rlk 为一次性；结果密文分发 E→P1，部分解密往返 = P1→P2 全密文 + P2→P1 两多项式"))
	lx := 36
	for i, n := range names {
		b.WriteString(rect(lx, 60, 12, 12, colors[i]))
		b.WriteString(text(lx+17, 70, "start", 12, "", txtMid, n))
		lx += 17 + 12 + int(strWidth(n, 12)) + 18
	}

	y := 100
	for _, r := range rows {
		b.WriteString(text(plotX-12, y+18, "end", 13, "", txtMid, r.label))
		x := plotX
		end := plotX
		for _, s := range r.segs {
			sw := int(s.v / maxV * float64(plotW))
			b.WriteString(rect(x, y, sw, 26, colors[s.ci]))
			if sw >= 34 {
				fill := txtMid
				if s.ci == 1 || s.ci == 2 || s.ci == 4 {
					fill = "#FFFFFF"
				}
				b.WriteString(text(x+sw/2, y+17, "middle", 12, "", fill, fmt.Sprintf("%g", s.v)))
			}
			x += sw
			end = x
		}
		b.WriteString(text(end+8, y+18, "start", 13, "bold", txtDark, r.total))
		y += 50
	}
	b.WriteString(text(W/2, 300, "middle", 12, "", txtGray,
		"“P1 兼任求值方”部署下在线通信显著下降：pn14 33.75 MiB（353.9 B/条），pn15QP660 75 MiB（786.4 B/条）"))
	save("fig2-comm.svg", W, H, b.String())
}

// ---------------- fig 3: per-MulRelin cost ----------------

func figMulCost() {
	const W, H = 820, 276
	const plotX, plotW = 310, 400
	const maxV = 2800.0

	rows := []struct {
		label string
		v     float64
		lab   string
		fill  string
	}{
		{"pn14（N=2^14, 6 limbs, β=6）", 169.7, "169.7 ms（×1.0，实测）", blueMid},
		{"pn15QP660（N=2^15, 10 limbs, β=10）", 1410, "1410 ms（×8.3，实测）", orange},
		{"pn15QP880（N=2^15, 14 limbs, β=14）", 2400, "≈2.1–2.8 s（估算）", "url(#hatch)"},
	}

	var b strings.Builder
	b.WriteString(`<defs><pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="6" height="6" fill="#D9D9D9"/><line x1="0" y1="0" x2="0" y2="6" stroke="#909090" stroke-width="2"/></pattern></defs>`)
	b.WriteString(text(W/2, 26, "middle", 16, "bold", txtDark, "图 3：单次两方密文乘 MulRelinNew 耗时"))
	b.WriteString(text(W/2, 46, "middle", 12, "", txtGray,
		"每次乘法 ≈ 2 次 DecomposeBFV（R = Q·QMul 域）+ 4 次密钥外积 + 基扩展，成本 ∝ N × R-limb 数 × β"))
	y := 100
	for _, r := range rows {
		b.WriteString(text(plotX-12, y+18, "end", 13, "", txtMid, r.label))
		bw := int(r.v / maxV * float64(plotW))
		b.WriteString(rect(plotX, y, bw, 26, r.fill))
		b.WriteString(text(plotX+bw+8, y+18, "start", 12, "", txtMid, r.lab))
		y += 56
	}
	b.WriteString(text(W/2, 262, "middle", 12, "", txtGray,
		"pn15QP880 为原版参数，本机 CRS 生成需 >5 GB 内存无法实测；按成本模型（×1.96 于 QP660）外推 ≈ 2.1–2.8 s（相对 pn14 ×12–16）"))
	save("fig3-mulcost.svg", W, H, b.String())
}

// ---------------- fig 4: per-record online communication ----------------

func figPerRecord() {
	const W, H = 820, 306
	const plotX, plotW = 240, 440
	const maxV = 2148.9

	rows := []struct {
		label string
		v     float64
		lab   string
		fill  string
	}{
		{"明文 CSV（5 列 int64）", 40, "40 B（×1）", gray},
		{"pn14（P1 兼任求值方）", 353.9, "353.9 B（×8.8）", blueLight},
		{"pn14（外部求值方）", 1069.5, "1069.5 B（×26.7）", blueDark},
		{"pn15QP660（P1 兼任求值方）", 786.4, "786.4 B（×19.7）", orangeLt},
		{"pn15QP660（外部求值方）", 2148.9, "2148.9 B（×53.7）", orange},
	}

	var b strings.Builder
	b.WriteString(text(W/2, 26, "middle", 16, "bold", txtDark, "图 4：摊销到每条记录的在线通信量"))
	b.WriteString(text(W/2, 46, "middle", 12, "", txtGray,
		"在线通信总量 ÷ 100,000 条 ｜ 明文口径 = 5 列 × 8 B = 40 B/条 ｜ 一次性 setup（pk+rlk）另计"))
	y := 100
	for _, r := range rows {
		b.WriteString(text(plotX-12, y+17, "end", 13, "", txtMid, r.label))
		bw := int(r.v / maxV * float64(plotW))
		if bw < 2 {
			bw = 2
		}
		b.WriteString(rect(plotX, y, bw, 24, r.fill))
		b.WriteString(text(plotX+bw+8, y+17, "start", 12, "", txtMid, r.lab))
		y += 48
	}
	b.WriteString(text(W/2, 290, "middle", 12, "", txtGray,
		"放大的直接来源：密文按 RNS 展开（每系数每 limb 8 B）；降低手段——P1 兼任求值方（省 3 倍）、limb 位打包（估省 ~20%）"))
	save("fig4-perrecord.svg", W, H, b.String())
}

func main() {
	figPhaseTime()
	figComm()
	figMulCost()
	figPerRecord()
}
