#!/usr/bin/env bash
# ============================================================================
# run-tests.sh — dotproductnet 三场景集成测试（单容器/单机双进程）
#
# 依次执行 场景 × 参数集 × (eval,receiver) 组合 × 轮次：每轮 P1、P2 各起
# 一个 dotproductnet 进程，经 127.0.0.1 socket 通信，双方完整日志落盘；
# 结束后从日志提取摘要（在线时长 / socket 实收实发 / T 位数 / 正确性）
# 写入 $LOGDIR/net_summary.txt。
#
# 典型用法（容器内；docker run -v $PWD/logs:/logs 挂载日志目录）：
#   bash dotproductnet/run-tests.sh                  # s1-3 × pn14+pn15 × (e1,r1) × 3 轮（默认）
#   bash dotproductnet/run-tests.sh -c pn14          # 只跑 pn14
#   bash dotproductnet/run-tests.sh -m -n 1 -w 2000  # 4 角色组合 × 2000 行 × 1 轮（快速冒烟）
#
# 产物（tag = s<场景>_<conf>_e<eval>r<recv>_rep<轮>）：
#   $LOGDIR/net_<tag>_p{1,2}.log   每轮每方完整日志（阶段耗时表 + 通信量 + 正确性）
#   $LOGDIR/net_summary.txt        全部轮次摘要表 + 机器信息
#   $WORK/out/net_<tag>.csv        接收方结果 CSV
#   $WORK/data/s{1,2,3}/           输入 CSV（dotproduct -gen 确定性生成，行数匹配则跳过）
#   （$WORK 默认 = 脚本旁 netdata/，可用 -d 改）
#
# 注意：从 Windows 拷贝本文件后若 bash 报 '\r' 相关错误，先执行
#   sed -i 's/\r$//' dotproductnet/run-tests.sh
# ============================================================================
set -u

BASE=$(cd "$(dirname "$0")" && pwd)

CONF=all
SCENS="1 2 3"
REPS=3
ROWS=100000
EVAL=1
RECV=1
MATRIX=0
LOGDIR=""
WORK="$BASE/netdata"
BASEPORT=17001

usage() {
  cat <<'EOF'
用法: bash dotproductnet/run-tests.sh [选项]
  -c pn14|pn15|all   参数集（默认 all）
  -s 1,2,3           场景列表（默认 1,2,3）
  -n N               每组重复轮数（默认 3，正式数据取中位数用）
  -w N               每列行数（默认 100000）
  -e 1|2             求值方（默认 1；-m 时忽略）
  -r 1|2             结果接收方（默认 1；-m 时忽略）
  -m                 角色矩阵：跑 (eval,recv) ∈ {(1,1),(1,2),(2,1),(2,2)}
  -l DIR             日志目录（默认：/logs 可写则用，否则脚本旁 logs/）
  -d DIR             工作目录：输入数据/hosts/结果 CSV（默认脚本旁 netdata/）
  -b PORT            起始端口（默认 17001，每轮 +2 递增避免 TIME_WAIT 干扰）
  -h                 本帮助
EOF
  exit "${1:-0}"
}

die() { echo "run-tests.sh: $*" >&2; exit 1; }

while getopts ":c:s:n:w:e:r:ml:d:b:h" opt; do
  case $opt in
    c) CONF=$OPTARG ;;
    s) SCENS=$(echo "$OPTARG" | tr ',' ' ') ;;
    n) REPS=$OPTARG ;;
    w) ROWS=$OPTARG ;;
    e) EVAL=$OPTARG ;;
    r) RECV=$OPTARG ;;
    m) MATRIX=1 ;;
    l) LOGDIR=$OPTARG ;;
    d) WORK=$OPTARG ;;
    b) BASEPORT=$OPTARG ;;
    h) usage 0 ;;
    *) usage 2 ;;
  esac
done
shift $((OPTIND - 1))

case "$CONF" in
  pn14|pn15) CONFS="$CONF" ;;
  all)       CONFS="pn14 pn15" ;;
  *) die "-c 仅支持 pn14 | pn15 | all" ;;
esac
case "$REPS"    in ''|*[!0-9]*) die "-n 需为正整数" ;; esac
case "$ROWS"    in ''|*[!0-9]*) die "-w 需为正整数" ;; esac
case "$BASEPORT" in ''|*[!0-9]*) die "-b 需为正整数" ;; esac
[ "$EVAL" = 1 ] || [ "$EVAL" = 2 ] || die "-e 仅支持 1|2"
[ "$RECV" = 1 ] || [ "$RECV" = 2 ] || die "-r 仅支持 1|2"
for s in $SCENS; do
  case "$s" in 1|2|3) ;; *) die "场景编号仅支持 1|2|3" ;; esac
done

command -v dotproductnet >/dev/null 2>&1 || die "dotproductnet 不在 PATH（容器内为 /usr/local/bin/dotproductnet）"
command -v dotproduct    >/dev/null 2>&1 || die "dotproduct 不在 PATH（容器内为 /usr/local/bin/dotproduct）"

if [ $MATRIX -eq 1 ]; then
  COMBOS="1,1 1,2 2,1 2,2"
else
  COMBOS="$EVAL,$RECV"
fi

if [ -z "$LOGDIR" ]; then
  if [ -d /logs ] && [ -w /logs ]; then LOGDIR=/logs; else LOGDIR="$BASE/logs"; fi
fi
mkdir -p "$LOGDIR" "$WORK/out" || die "无法创建输出目录 $LOGDIR / $WORK/out"

# ---------- 输入数据（确定性 -gen，已存在且行数匹配则跳过） ----------

lines() {
  if [ -f "$1" ]; then wc -l < "$1" | tr -d ' \t\r\n'; else echo 0; fi
}

gen_data() {
  local s=$1
  local d="$WORK/data/s$s"
  local p2 want1 want2
  if [ "$s" = 1 ]; then p2=p2_weights.csv; else p2=p2_data.csv; fi
  want1=$((ROWS + 1))
  want2=2
  [ "$s" != 1 ] && want2=$((ROWS + 1))
  if [ "$(lines "$d/p1_data.csv")" = "$want1" ] && [ "$(lines "$d/$p2")" = "$want2" ]; then
    echo "[data] $d 已存在且行数匹配，跳过生成"
    return 0
  fi
  echo "[data] 生成 $d（rows=$ROWS，bound/seed 用场景默认值）"
  dotproduct -gen -scenario "$s" -rows "$ROWS" -gendir "$d" || die "scenario $s 数据生成失败"
}

# ---------- 单轮执行 ----------

IDX=0
FAILS=0
declare -a TAGS=() RECVS=() FAILEDTAGS=()

run_one() {
  local s=$1 conf=$2 ev=$3 rc=$4 rep=$5
  local tag="s${s}_${conf}_e${ev}r${rc}_rep${rep}"
  TAGS+=("$tag")
  RECVS+=("$rc")
  local pa=$((BASEPORT + IDX * 2)) pb=$((BASEPORT + IDX * 2 + 1))
  IDX=$((IDX + 1))
  local hf="$WORK/hosts_${tag}.txt"
  printf '127.0.0.1:%d\n127.0.0.1:%d\n' "$pa" "$pb" > "$hf"
  local d="$WORK/data/s$s"
  local p2f="$d/p2_data.csv"
  [ "$s" = 1 ] && p2f="$d/p2_weights.csv"
  local lp1="$LOGDIR/net_${tag}_p1.log" lp2="$LOGDIR/net_${tag}_p2.log"

  echo "=================================================================="
  echo ">>> $tag   ports $pa/$pb   $(date '+%F %T')"

  dotproductnet -party 2 -hostfile "$hf" -scenario "$s" -conf "$conf" \
    -eval "$ev" -receiver "$rc" \
    -p1 "$d/p1_data.csv" -p2 "$p2f" -out "$WORK/out/net_${tag}.csv" \
    > "$lp2" 2>&1 &
  local bg=$!

  dotproductnet -party 1 -hostfile "$hf" -scenario "$s" -conf "$conf" \
    -eval "$ev" -receiver "$rc" \
    -p1 "$d/p1_data.csv" -p2 "$p2f" -out "$WORK/out/net_${tag}.csv" \
    2>&1 | tee "$lp1"
  local st1=${PIPESTATUS[0]}
  wait "$bg"
  local st2=$?

  local ok=1
  [ "$st1" -ne 0 ] && { echo "!! P1 退出码 $st1"; ok=0; }
  [ "$st2" -ne 0 ] && { echo "!! P2 退出码 $st2"; ok=0; }
  grep -q "correctness: OK" "$LOGDIR/net_${tag}_p${rc}.log" || { echo "!! 接收方 P$rc 验证未通过"; ok=0; }
  if [ "$ok" = 1 ]; then
    echo ">>> $tag OK"
  else
    FAILS=$((FAILS + 1))
    FAILEDTAGS+=("$tag")
    echo "!! $tag 失败，双方日志尾部："
    tail -n 15 "$lp1" "$lp2"
  fi
}

# ---------- 主循环 ----------

echo "run-tests: scenarios=[$SCENS] params=[$CONFS] combos=[$COMBOS] reps=$REPS rows=$ROWS"
echo "           logdir=$LOGDIR workdir=$WORK GOGC=${GOGC:-unset} host=$(hostname 2>/dev/null || echo '?')"

for s in $SCENS; do
  gen_data "$s"
done

for s in $SCENS; do
  for conf in $CONFS; do
    for combo in $COMBOS; do
      ev=${combo%,*}
      rc=${combo#*,}
      for rep in $(seq 1 "$REPS"); do
        run_one "$s" "$conf" "$ev" "$rc" "$rep"
      done
    done
  done
done

# ---------- 摘要 ----------

summarize() {
  local i tag p lg on sr sent recv corr tbits
  {
    echo "=============================================================="
    echo "MKHE dotproductnet 集成测试摘要"
    date '+%F %T'
    echo "host : $(uname -srmo) | cores: $(nproc 2>/dev/null || echo '?') | $(grep -m1 MemTotal /proc/meminfo 2>/dev/null | awk '{printf "%.1f GB RAM", $2/1024/1024}')"
    echo "conf : scenarios=[$SCENS] params=[$CONFS] combos=[$COMBOS] reps=$REPS rows=$ROWS GOGC=${GOGC:-unset}"
    echo "=============================================================="
    printf '%-26s %-4s %-6s %-11s %-11s %-11s %-11s %s\n' run party Tbits online sent recv correctness
    printf '%s\n' "--------------------------------------------------------------------------------------------"
    for i in "${!TAGS[@]}"; do
      tag=${TAGS[$i]}
      for p in 1 2; do
        lg="$LOGDIR/net_${tag}_p${p}.log"
        [ -f "$lg" ] || continue
        on=$(sed -n 's/^total time online (keygen->result): //p' "$lg" | tail -n 1)
        sr=$(sed -n 's/^socket bytes sent\/recv *| //p' "$lg" | tail -n 1)
        sent=$(echo "$sr" | cut -d/ -f1 | tr -d ' ')
        recv=$(echo "$sr" | cut -d/ -f2 | tr -d ' ')
        tbits="-"
        [ "$p" = 1 ] && tbits=$(sed -n 's/^  conf=[^(]*(\([0-9]*\) bits.*/\1/p' "$lg" | tail -n 1)
        corr=""
        [ "$p" = "${RECVS[$i]}" ] && corr=$(sed -n 's/^correctness: //p' "$lg" | tail -n 1)
        printf '%-26s P%-3d %-6s %-11s %-11s %-11s %-11s %s\n' \
          "$tag" "$p" "${tbits:--}" "${on:--}" "${sent:--}" "${recv:--}" "${corr:--}"
      done
    done
    echo "--------------------------------------------------------------"
    if [ "$FAILS" = 0 ]; then
      echo "结果: 全部 ${#TAGS[@]} 轮通过（双方退出码 0 且接收方 correctness: OK）"
    else
      echo "结果: ${FAILS} 轮失败: ${FAILEDTAGS[*]}"
    fi
  } | tee "$LOGDIR/net_summary.txt"
}

summarize

if [ "$FAILS" -ne 0 ]; then
  exit 1
fi
echo "完成。日志: $LOGDIR/net_*.log；摘要: $LOGDIR/net_summary.txt"
