package org.example.controller;

import org.example.config.FileUploadConfig;
import org.example.dto.FileUploadRes;
import org.example.security.PathSecurityUtil;
import org.example.security.SensitiveContentScanner;
import org.example.service.VectorIndexService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class FileUploadController {

    private static final Logger logger = LoggerFactory.getLogger(FileUploadController.class);

    @Autowired
    private FileUploadConfig fileUploadConfig;

    @Autowired
    private VectorIndexService vectorIndexService;

    /** 敏感内容扫描：严格模式下中危口令也拦截，默认只拦截高危凭据 */
    @Value("${file.upload.sensitive-strict:false}")
    private boolean sensitiveStrict;

    /** 是否开启入库前敏感信息扫描 */
    @Value("${file.upload.sensitive-scan:true}")
    private boolean sensitiveScan;

    @PostMapping(value = "/api/upload", consumes = "multipart/form-data")
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "文件不能为空"));
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.isEmpty()) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "文件名不能为空"));
        }

        Set<String> allowedExts = parseAllowedExtensions(fileUploadConfig.getAllowedExtensions());

        // 安全校验：白名单净化文件名 + 扩展名，防御路径穿越（CWE-22）
        String safeName;
        try {
            safeName = PathSecurityUtil.sanitizeFileName(originalFilename, allowedExts);
        } catch (PathSecurityUtil.InvalidFileNameException e) {
            logger.warn("拒绝上传非法文件名 [{}]: {}", originalFilename, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(400, "非法文件名：" + e.getMessage()));
        }

        try {
            // 一次性读取内容（敏感扫描 + 落盘共用，避免重复消费流）
            byte[] bytes = file.getBytes();
            String content = new String(bytes, StandardCharsets.UTF_8);

            // 入库前敏感信息扫描（DLP），防止凭据/私钥进入知识库
            if (sensitiveScan) {
                List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(content);
                if (SensitiveContentScanner.shouldBlock(findings, sensitiveStrict)) {
                    List<String> reasons = findings.stream()
                            .map(f -> f.getSeverity() + ":" + f.getRule())
                            .collect(Collectors.toList());
                    logger.warn("文件 [{}] 含敏感信息，已拦截入库: {}", safeName, reasons);
                    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                            .body(ApiResponse.error(422, "文档中检测到敏感凭据（如密钥/私钥），已拦截：" + reasons));
                }
                if (!findings.isEmpty()) {
                    logger.warn("文件 [{}] 存在低风险敏感信息告警: {}", safeName,
                            findings.stream().map(SensitiveContentScanner.Finding::getRule).collect(Collectors.toList()));
                }
            }

            String uploadPath = fileUploadConfig.getPath();
            Path uploadDir = Paths.get(uploadPath).normalize();
            if (!Files.exists(uploadDir)) {
                Files.createDirectories(uploadDir);
            }

            // 落盘路径必须位于上传根目录内
            Path filePath = PathSecurityUtil.resolveWithin(uploadDir, safeName);

            // 覆盖更新（同名文件）
            Files.deleteIfExists(filePath);
            Files.write(filePath, bytes);

            logger.info("文件上传成功: {}", filePath);

            // 自动创建向量索引
            try {
                logger.info("开始为上传文件创建向量索引: {}", filePath);
                vectorIndexService.indexSingleFile(filePath.toString());
                logger.info("向量索引创建成功: {}", filePath);
            } catch (Exception e) {
                logger.error("向量索引创建失败: {}, 错误: {}", filePath, e.getMessage(), e);
            }

            FileUploadRes response = new FileUploadRes(
                    safeName,
                    filePath.toString(),
                    file.getSize()
            );

            return ResponseEntity.ok(ApiResponse.success(response));

        } catch (Exception e) {
            logger.error("文件上传失败", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error(500, "文件上传失败，请检查服务端日志"));
        }
    }

    private Set<String> parseAllowedExtensions(String allowedExtensions) {
        if (allowedExtensions == null || allowedExtensions.isEmpty()) {
            return new HashSet<>();
        }
        return Arrays.stream(allowedExtensions.split(","))
                .map(String::trim)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
    }

    /**
     * 统一 API 响应格式
     */
    public static class ApiResponse<T> {
        private int code;
        private String message;
        private T data;

        public static <T> ApiResponse<T> success(T data) {
            ApiResponse<T> r = new ApiResponse<>();
            r.code = 200;
            r.message = "success";
            r.data = data;
            return r;
        }

        public static <T> ApiResponse<T> error(int code, String message) {
            ApiResponse<T> r = new ApiResponse<>();
            r.code = code;
            r.message = message;
            return r;
        }

        public int getCode() {
            return code;
        }

        public void setCode(int code) {
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public T getData() {
            return data;
        }

        public void setData(T data) {
            this.data = data;
        }
    }
}
