# SecAgent Makefile（Linux/macOS 便利脚本；Windows 用户推荐直接用 IDEA，见 docs/00-从零运行傻瓜手册-Windows.md）
#
# 默认 vector.store=memory（内存向量库），预置 318 条向量开箱即用，无需 Docker。
# 仅当你把 application.yml 改为 vector.store=milvus 时，才需要 make up 启动 Milvus。

# 配置变量
SERVER_URL = http://localhost:9900
UPLOAD_API = $(SERVER_URL)/api/upload
HEALTH_CHECK_API = $(SERVER_URL)/api/health
DOCS_DIR = security-docs
DOCKER_COMPOSE_FILE = vector-database.yml
MILVUS_CONTAINER = milvus-standalone

# 颜色输出
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help init start stop restart check upload clean up down status wait

# 默认目标：显示帮助信息
help:
	@echo "$(GREEN)SecAgent Makefile$(NC)"
	@echo ""
	@echo "默认内存模式（无需 Docker，推荐）："
	@echo "  $(YELLOW)make init$(NC)    - 启动 Spring Boot 服务并等待就绪（预置向量开箱即用）"
	@echo "  $(YELLOW)make start$(NC)   - 后台启动 Spring Boot 服务"
	@echo "  $(YELLOW)make stop$(NC)    - 停止服务"
	@echo "  $(YELLOW)make restart$(NC) - 重启服务"
	@echo "  $(YELLOW)make check$(NC)   - 健康检查（/api/health）"
	@echo "  $(YELLOW)make upload$(NC)  - 额外批量上传 security-docs 到知识库（可选）"
	@echo ""
	@echo "仅 Milvus 模式（先在 application.yml 设置 vector.store=milvus）："
	@echo "  $(YELLOW)make up$(NC)      - 启动 Docker Compose（Milvus）"
	@echo "  $(YELLOW)make down$(NC)    - 停止 Docker Compose"
	@echo "  $(YELLOW)make status$(NC)  - 查看 Milvus 容器状态"
	@echo "  $(YELLOW)make clean$(NC)   - 清理临时文件"

# 一键初始化（内存模式：启动服务 → 等待就绪；知识库使用预置向量）
init:
	@echo "$(GREEN)🚀 开始初始化 SecAgent（内存向量模式）...$(NC)"
	@$(MAKE) start
	@$(MAKE) wait
	@echo ""
	@echo "$(GREEN)✅ 初始化完成！预置安全知识库已就绪（318 条向量）。$(NC)"
	@echo "   浏览器访问: $(SERVER_URL)"

# 启动 Spring Boot 服务（后台运行）
start:
	@echo "$(YELLOW)🚀 启动 Spring Boot 服务...$(NC)"
	@if curl -s -f $(HEALTH_CHECK_API) > /dev/null 2>&1; then \
		echo "$(GREEN)✅ 服务已在运行中 ($(SERVER_URL))$(NC)"; \
	else \
		echo "$(YELLOW)📦 正在后台启动（首次需下载依赖，请耐心等待）...$(NC)"; \
		nohup mvn spring-boot:run > server.log 2>&1 & echo $$! > server.pid; \
		echo "$(YELLOW)   日志: tail -f server.log$(NC)"; \
	fi

# 等待服务就绪（最多 120 秒）
wait:
	@echo "$(YELLOW)⏳ 等待服务就绪...$(NC)"
	@max_attempts=120; attempt=0; \
	while [ $$attempt -lt $$max_attempts ]; do \
		if curl -s -f $(HEALTH_CHECK_API) > /dev/null 2>&1; then \
			echo "$(GREEN)✅ 服务已就绪 ($(SERVER_URL))$(NC)"; exit 0; \
		fi; \
		attempt=$$((attempt + 1)); printf "   等待中... [$$attempt/$$max_attempts]\r"; sleep 1; \
	done; \
	echo ""; echo "$(RED)❌ 启动超时，请检查 server.log（常见原因：未配置 DASHSCOPE_API_KEY）$(NC)"; exit 1

# 健康检查
check:
	@if curl -s -f $(HEALTH_CHECK_API) > /dev/null 2>&1; then \
		echo "$(GREEN)✅ 服务运行正常$(NC)"; curl -s $(HEALTH_CHECK_API); echo; \
	else \
		echo "$(RED)❌ 服务未运行，请先 make start（或在 IDEA 运行 Main）$(NC)"; exit 1; \
	fi

# 批量上传知识库文档（可选；默认已预置向量）
upload:
	@echo "$(YELLOW)📤 上传 $(DOCS_DIR) 目录下的文档...$(NC)"
	@[ -d "$(DOCS_DIR)" ] || { echo "$(RED)❌ 目录 $(DOCS_DIR) 不存在$(NC)"; exit 1; }
	@count=0; success=0; failed=0; \
	for file in $(DOCS_DIR)/*.md; do \
		[ -f "$$file" ] || continue; \
		count=$$((count + 1)); filename=$$(basename "$$file"); \
		http_code=$$(curl -s -o /dev/null -w "%{http_code}" -X POST $(UPLOAD_API) -F "file=@$$file" -H "Accept: application/json"); \
		if [ "$$http_code" = "200" ]; then echo "  $(GREEN)✅ $$filename$(NC)"; success=$$((success + 1)); \
		else echo "  $(RED)❌ $$filename (HTTP $$http_code)$(NC)"; failed=$$((failed + 1)); fi; \
	done; \
	echo "$(GREEN)完成：成功 $$success / 总计 $$count$(NC)"; \
	[ $$failed -eq 0 ] || exit 1

# 停止服务
stop:
	@if [ -f server.pid ]; then \
		kill $$(cat server.pid) 2>/dev/null && echo "$(GREEN)✅ 服务已停止$(NC)" || echo "$(YELLOW)进程已结束$(NC)"; rm -f server.pid; \
	else \
		pkill -f "spring-boot:run" && echo "$(GREEN)✅ 已停止 spring-boot 进程$(NC)" || echo "$(YELLOW)没有运行中的进程$(NC)"; \
	fi

# 重启
restart:
	@$(MAKE) stop
	@$(MAKE) start
	@$(MAKE) wait

# 清理
clean:
	@rm -f server.pid server.log
	@echo "$(GREEN)✅ 已清理临时文件（如需清空内存向量库，删除 data/vector-store.json）$(NC)"

# ============ 仅 Milvus 模式（可选） ============
up:
	@[ -f "$(DOCKER_COMPOSE_FILE)" ] || { echo "$(RED)❌ 缺少 $(DOCKER_COMPOSE_FILE)$(NC)"; exit 1; }
	@echo "$(YELLOW)🐳 启动 Milvus（请确认 application.yml 中 vector.store=milvus）...$(NC)"
	docker compose -f $(DOCKER_COMPOSE_FILE) up -d

down:
	@[ -f "$(DOCKER_COMPOSE_FILE)" ] || { echo "$(RED)❌ 缺少 $(DOCKER_COMPOSE_FILE)$(NC)"; exit 1; }
	docker compose -f $(DOCKER_COMPOSE_FILE) down

status:
	@docker ps -a --filter "name=milvus" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || true
