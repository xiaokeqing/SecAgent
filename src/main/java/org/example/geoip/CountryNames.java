package org.example.geoip;

import java.util.HashMap;
import java.util.Map;

/**
 * ISO-3166-1 alpha-2 → 中文展示名（<b>只用于展示</b>，不参与任何判定与聚合键）。
 *
 * <h3>为什么不是把中文名写进库里</h3>
 * 库（DB-IP）给的是 {@code country_code}（ISO2，例如 {@code CN}）与英文的省/城市名。
 * 聚合键必须用 ISO2（稳定、唯一、前端做中国地图时判定"是不是国内"也只看它），
 * 中文名只是给页面用的标签 —— 两者混在一起会出现"某天数据源把 China 写成 China mainland，
 * 于是国内省份榜空了"这种不会报错的故障。
 *
 * <h3>覆盖范围与兜底</h3>
 * 这里只列常见国家（够覆盖实测出现过的来源地）；<b>没列到的一律回落到 ISO2 原码</b>，
 * 于是"没收录"表现为"页面上显示 US 而不是美国"，而不是空字符串。
 * 收录不全会让它看起来有点土，但永远不会让数据错位 —— 这是刻意的取舍。
 */
public final class CountryNames {

    private CountryNames() {
    }

    private static final Map<String, String> ZH = new HashMap<>(128);

    private static void put(String code, String name) {
        ZH.put(code, name);
    }

    static {
        put("CN", "中国");
        put("HK", "中国香港");
        put("MO", "中国澳门");
        put("TW", "中国台湾");
        put("US", "美国");
        put("JP", "日本");
        put("KR", "韩国");
        put("KP", "朝鲜");
        put("RU", "俄罗斯");
        put("IN", "印度");
        put("ID", "印度尼西亚");
        put("VN", "越南");
        put("TH", "泰国");
        put("MY", "马来西亚");
        put("SG", "新加坡");
        put("PH", "菲律宾");
        put("MM", "缅甸");
        put("KH", "柬埔寨");
        put("LA", "老挝");
        put("BD", "孟加拉国");
        put("PK", "巴基斯坦");
        put("NP", "尼泊尔");
        put("LK", "斯里兰卡");
        put("KZ", "哈萨克斯坦");
        put("UZ", "乌兹别克斯坦");
        put("MN", "蒙古");
        put("AE", "阿联酋");
        put("SA", "沙特阿拉伯");
        put("IL", "以色列");
        put("TR", "土耳其");
        put("IR", "伊朗");
        put("IQ", "伊拉克");
        put("QA", "卡塔尔");
        put("KW", "科威特");
        put("BH", "巴林");
        put("OM", "阿曼");
        put("JO", "约旦");
        put("LB", "黎巴嫩");
        put("SY", "叙利亚");
        put("GE", "格鲁吉亚");
        put("AM", "亚美尼亚");
        put("AZ", "阿塞拜疆");
        put("GB", "英国");
        put("IE", "爱尔兰");
        put("FR", "法国");
        put("DE", "德国");
        put("NL", "荷兰");
        put("BE", "比利时");
        put("LU", "卢森堡");
        put("CH", "瑞士");
        put("AT", "奥地利");
        put("IT", "意大利");
        put("ES", "西班牙");
        put("PT", "葡萄牙");
        put("GR", "希腊");
        put("SE", "瑞典");
        put("NO", "挪威");
        put("DK", "丹麦");
        put("FI", "芬兰");
        put("IS", "冰岛");
        put("PL", "波兰");
        put("CZ", "捷克");
        put("SK", "斯洛伐克");
        put("HU", "匈牙利");
        put("RO", "罗马尼亚");
        put("BG", "保加利亚");
        put("UA", "乌克兰");
        put("BY", "白俄罗斯");
        put("MD", "摩尔多瓦");
        put("LT", "立陶宛");
        put("LV", "拉脱维亚");
        put("EE", "爱沙尼亚");
        put("RS", "塞尔维亚");
        put("HR", "克罗地亚");
        put("SI", "斯洛文尼亚");
        put("BA", "波黑");
        put("MK", "北马其顿");
        put("AL", "阿尔巴尼亚");
        put("MT", "马耳他");
        put("CY", "塞浦路斯");
        put("CA", "加拿大");
        put("MX", "墨西哥");
        put("BR", "巴西");
        put("AR", "阿根廷");
        put("CL", "智利");
        put("CO", "哥伦比亚");
        put("PE", "秘鲁");
        put("VE", "委内瑞拉");
        put("EC", "厄瓜多尔");
        put("UY", "乌拉圭");
        put("PY", "巴拉圭");
        put("BO", "玻利维亚");
        put("CR", "哥斯达黎加");
        put("PA", "巴拿马");
        put("CU", "古巴");
        put("DO", "多米尼加");
        put("GT", "危地马拉");
        put("AU", "澳大利亚");
        put("NZ", "新西兰");
        put("ZA", "南非");
        put("EG", "埃及");
        put("NG", "尼日利亚");
        put("KE", "肯尼亚");
        put("MA", "摩洛哥");
        put("DZ", "阿尔及利亚");
        put("TN", "突尼斯");
        put("LY", "利比亚");
        put("SD", "苏丹");
        put("ET", "埃塞俄比亚");
        put("GH", "加纳");
        put("TZ", "坦桑尼亚");
        put("UG", "乌干达");
        put("ZW", "津巴布韦");
        put("ZM", "赞比亚");
        put("MZ", "莫桑比克");
        put("AO", "安哥拉");
        put("CM", "喀麦隆");
        put("CI", "科特迪瓦");
        put("SN", "塞内加尔");
        put("ML", "马里");
        put("BF", "布基纳法索");
        put("SC", "塞舌尔");
        put("MU", "毛里求斯");
        put("MG", "马达加斯加");
        put("BW", "博茨瓦纳");
        put("NA", "纳米比亚");
    }

    /**
     * 中文展示名；未收录返回 ISO2 原码（大写），{@code null}/空/ZZ 返回 {@code null}。
     *
     * <p>{@code ZZ} 是 DB-IP 对"未分配/未知"的占位国家码，它<b>不是</b>一个国家，
     * 所以这里返回 null，让调用方走"未定位"分支。
     */
    public static String of(String iso2) {
        if (iso2 == null) {
            return null;
        }
        String code = iso2.trim().toUpperCase(java.util.Locale.ROOT);
        if (code.isEmpty() || "ZZ".equals(code)) {
            return null;
        }
        String zh = ZH.get(code);
        return zh != null ? zh : code;
    }

    /** 收录了多少个国家（测试用；防止有人把这张表清空后测试还绿着） */
    public static int size() {
        return ZH.size();
    }
}
