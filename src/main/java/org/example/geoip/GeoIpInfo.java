package org.example.geoip;

/**
 * 一次 IP → 地理位置查询的结果（不可变值对象）。
 *
 * <h3>为什么字段全是英文原样值，而不是预先拼成中文</h3>
 * 数据源是 DB-IP Lite（CC BY 4.0），它给的 {@code country_code} 是 ISO-3166-1 alpha-2、
 * {@code subdivision_1} 与城市名是英文原文（{@code Zhejiang} / {@code Hangzhou}）。
 * 这里<b>原样保留</b>，中文展示名由 {@link CountryNames} 单独换算 ——
 * 因为"给中国地图用的省名"和"给人看的城市名"是两件事，
 * 在数据层拼一次字符串会让两边的口径都改不动（实测过：把省名拼成中文后，
 * 前端按 DB-IP 原文做的省份路径匹配全对不上）。
 *
 * <h3>srcGeo 的最终形状（本类 {@link #describe()}）</h3>
 * <pre>
 *   国家ISO2|一级行政区|城市|ASN|AS组织       例：CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE
 *   未知的每一段写 "-"（不写空串，分段数恒定，前端 split 后下标才有意义）
 * </pre>
 * 该字符串赋给 {@link org.example.core.model.SecurityAlert#getSrcGeo()}，<b>仅内部可见</b>：
 * 公开面（{@code /api/public/**}）只输出国家/省份级聚合，绝不逐条输出它 ——
 * 逐条的地理+ASN 等于把"某个攻击者属于哪个机构"直接搬上公网页面。
 */
public final class GeoIpInfo {

    /** 空结果（IP 不在库里 / 私有地址 / 解析失败）：刻意不是 null，避免调用方到处判空 */
    public static final GeoIpInfo UNKNOWN = new GeoIpInfo(null, null, null, 0, null);

    private final String country;    // ISO-3166-1 alpha-2，大写；未知为 null
    private final String province;   // DB-IP subdivision_1（英文原文）
    private final String city;       // DB-IP city（英文原文）
    private final int asn;           // 自治系统号；0 表示未知
    private final String asnOrg;     // 机构名（DB-IP as_name）

    public GeoIpInfo(String country, String province, String city, int asn, String asnOrg) {
        this.country = blankToNull(country);
        this.province = blankToNull(province);
        this.city = blankToNull(city);
        this.asn = asn;
        this.asnOrg = blankToNull(asnOrg);
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }

    public String getCountry() {
        return country;
    }

    public String getProvince() {
        return province;
    }

    public String getCity() {
        return city;
    }

    public int getAsn() {
        return asn;
    }

    public String getAsnOrg() {
        return asnOrg;
    }

    /** 是否至少定位到了国家 —— "能不能上地图"的唯一判据（只有 ASN 不算） */
    public boolean hasCountry() {
        return country != null && !"ZZ".equalsIgnoreCase(country);
    }

    /** 有没有任何有效信息（国家或 ASN 至少一个） */
    public boolean isKnown() {
        return hasCountry() || asn > 0;
    }

    /**
     * {@code srcGeo} 的最终形状：{@code 国家|省|城市|ASN|AS组织}，未知段写 {@code -}。
     *
     * @return 定位不到任何信息时返回 {@code null}（保持"空即未知"的既有语义，不造假字符串）
     */
    public String describe() {
        if (!isKnown()) {
            return null;
        }
        return dash(country) + "|" + dash(province) + "|" + dash(city) + "|"
                + (asn > 0 ? String.valueOf(asn) : "-") + "|" + dash(asnOrg);
    }

    private static String dash(String s) {
        return s == null ? "-" : s;
    }

    @Override
    public String toString() {
        return describe() == null ? "GeoIpInfo{unknown}" : describe();
    }
}
