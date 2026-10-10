package org.example.security;

/**
 * 系统角色（RBAC）。
 * ADMIN 管理员：可查看、可处置、可审核知识库、可管理用户；
 * ANALYST 分析员：可查看告警/日志/事件、可对话研判、可提交知识，但不能执行处置与审核。
 */
public enum Role {

    ADMIN("管理员"),
    ANALYST("分析员");

    private final String label;

    Role(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public static Role parse(Object raw) {
        if (raw == null) {
            return ANALYST;
        }
        String s = String.valueOf(raw).trim().toUpperCase();
        if (s.contains("ADMIN")) {
            return ADMIN;
        }
        return ANALYST;
    }
}
