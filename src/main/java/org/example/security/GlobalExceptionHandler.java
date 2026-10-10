package org.example.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 全局异常处理。
 *
 * <p>原始代码大量在业务异常时返回 HTTP 200，且异常信息可能直接把堆栈/内部路径暴露给客户端。
 * 这里统一收敛：对外只返回状态码与可读消息，详细堆栈仅记录到服务端日志。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** 非法文件名 / 路径穿越 */
    @ExceptionHandler(PathSecurityUtil.InvalidFileNameException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidFileName(PathSecurityUtil.InvalidFileNameException e) {
        logger.warn("非法文件名请求: {}", e.getMessage());
        return build(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    /** 上传文件超过大小限制 */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> handleUploadSize(MaxUploadSizeExceededException e) {
        logger.warn("上传文件过大: {}", e.getMessage());
        return build(HttpStatus.PAYLOAD_TOO_LARGE, "上传文件超过大小限制");
    }

    /** 非法参数 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArg(IllegalArgumentException e) {
        logger.warn("非法参数: {}", e.getMessage());
        return build(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    /** 兜底：不向客户端泄露内部堆栈 */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception e) {
        logger.error("未处理异常", e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "服务器内部错误，请联系管理员查看服务端日志");
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status.value());
        body.put("message", message);
        return ResponseEntity.status(status).body(body);
    }
}
