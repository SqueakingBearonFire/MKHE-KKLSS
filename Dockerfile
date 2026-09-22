# ============================================================================
# MKHE-KKLSS : MK-BFV two-party weighted-sum (dot-product) benchmark toolbox
#
# Builds the CSV end-to-end CLI (-> /usr/local/bin/dotproduct, on PATH) and
# the two-process networked runner (-> /usr/local/bin/dotproductnet).
# Nothing runs automatically: start an interactive shell and run commands
# manually. All command examples: doc/dotproduct-report.md (Section 6) and
# doc/dotproduct-net.md.
#
#   docker build -t mkhe-dotproduct .
#   docker run -it --rm mkhe-dotproduct            # enter a shell at /app
#   docker run -it --rm -m 12g -e GOGC=200 mkhe-dotproduct
# ============================================================================
FROM docker.oa.com:5100/base/docker-cli-golang:1.23.7

# GO 环境变量（参考 collector Dockerfile 的内网配置：goproxy.cn 代理 +
# git.code.tencent.com 私有仓库直连/跳过校验）。
# 差异两处：本项目纯 Go 无 cgo -> CGO_ENABLED=0（静态编译更通用）；
# 附带 TZ 与 GOGC（pn15 大堆场景 GC 调优，可 run 时覆盖）。
ENV GOPROXY=https://goproxy.cn,direct \
    GO111MODULE=on \
    GOOS=linux \
    CGO_ENABLED=0 \
    GONOPROXY=git.code.tencent.com \
    GONOSUMDB=git.code.tencent.com \
    GOPRIVATE=git.code.tencent.com \
    GOINSECURE=git.code.tencent.com \
    TZ=Asia/Shanghai \
    GOGC=200

WORKDIR /app

# dependency layer (cached)
COPY go.mod ./
RUN go mod download

# source + build the CLIs
COPY . .
RUN go build -trimpath -o /usr/local/bin/dotproduct ./dotproduct && \
    go build -trimpath -o /usr/local/bin/dotproductnet ./dotproductnet

# 显式钉死入口为 bash：覆盖基础镜像可能自带的 ENTRYPOINT/CMD，
# 保证 docker run 不自动执行任何业务代码，进容器后手动输入指令运行
# （命令清单：doc/dotproduct-report.md 第六节）
ENTRYPOINT ["bash"]
