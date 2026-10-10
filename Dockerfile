# syntax=docker/dockerfile:1

# ============================================================
# SecAgent 镜像
# ------------------------------------------------------------
# 多阶段构建：构建阶段包含完整 Maven 与 JDK，运行阶段只留 JRE。
#
# ⚠️ 构建阶段会下载依赖并编译，内存占用较大。
#    请在开发机或 CI 上执行 docker build，不要在低配云服务器
#    上直接构建（2C2G 很容易 OOM 卡死）。
#    推荐流程：GitHub Actions 构建 → 推送到镜像仓库 → 服务器只 pull。
# ============================================================

# ---------- 阶段 1：构建 ----------
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build

# 依赖单独一层：只要 pom.xml 没变就命中缓存，避免每次重新下载
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q clean package -DskipTests

# ---------- 阶段 2：运行 ----------
FROM eclipse-temurin:17-jre-jammy

# 中文字体是必需的，不是可选优化：
#   EventPdfService 硬编码读取 /usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc
#   （ttc 索引 3 = 简体中文，索引 5 = 等宽），缺失时导出的 PDF 中文会变成方块。
# tzdata 用于把容器时区固定为 Asia/Shanghai，避免日志与审计时间错乱。
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tzdata \
      fonts-noto-cjk \
      ca-certificates \
      curl \
 && rm -rf /var/lib/apt/lists/* \
 && ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
 && echo "Asia/Shanghai" > /etc/timezone \
 && test -f /usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc

WORKDIR /app

# 以非 root 用户运行：容器被拿下时限制影响面
RUN groupadd -r secagent \
 && useradd -r -g secagent -d /app -s /usr/sbin/nologin secagent

COPY --from=build /build/target/*.jar /app/app.jar
COPY security-docs /app/security-docs

# 运行时数据目录（data/ 与 uploads/ 由 docker-compose 挂载卷持久化）
RUN mkdir -p /app/data /app/uploads \
 && chown -R secagent:secagent /app

USER secagent

EXPOSE 9900

# JVM 参数刻意做成可覆盖：不同规格的机器需要不同的堆上限。
# 默认值按 4G 内存主机设定。
#   -Xmx1g                    堆上限，不设会按物理内存 1/4 取，可能把机器吃干
#   -XX:MaxMetaspaceSize=256m Spring 系类元数据多，不限制会持续增长
#   -XX:+UseSerialGC          小堆场景下比 G1 更省内存与线程
#   -XX:+ExitOnOutOfMemoryError  OOM 直接退出交给容器重启，避免僵死
#   HeapDumpOnOutOfMemoryError  出问题时留下现场，便于定位
ENV JAVA_OPTS="-Xms256m -Xmx1g -XX:MaxMetaspaceSize=256m -XX:+UseSerialGC -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/app/data -Duser.timezone=Asia/Shanghai -Dfile.encoding=UTF-8"

# start-period 给足：低配机器上 Spring 上下文初始化较慢
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
  CMD curl -fsS http://localhost:9900/api/health || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
