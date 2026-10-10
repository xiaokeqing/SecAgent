package org.example.event;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * 单事件 PDF 报告生成（OpenPDF / iText 分支）。
 *
 * <p>中文字体：Noto Sans CJK Regular 集合中简体中文（SC，ttc 索引 3），
 * 以 IDENTITY_H + EMBEDDED 方式嵌入，保证跨机器打开中文不乱码。
 * IOC / 证据原文用等宽中文字体同样式渲染。
 */
@Service
public class EventPdfService {

    private static final Logger logger = LoggerFactory.getLogger(EventPdfService.class);

    /** NotoSansCJK-Regular.ttc 内字体顺序：0=JP 1=HK 2=KR 3=SC 4=TC ... */
    private static final String CJK_TTC = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc,3";
    private static final String CJK_MONO_TTC = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc,5";

    private Font cjkTitle;
    private Font cjkHead;
    private Font cjkBody;
    private Font cjkMono;
    private boolean fontOk;

    public EventPdfService() {
        try {
            BaseFont bf = BaseFont.createFont(CJK_TTC, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
            cjkTitle = new Font(bf, 20, Font.BOLD);
            cjkHead = new Font(bf, 13, Font.BOLD);
            cjkBody = new Font(bf, 10.5f, Font.NORMAL);
            BaseFont bfMono = BaseFont.createFont(CJK_MONO_TTC, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
            cjkMono = new Font(bfMono, 9.5f, Font.NORMAL);
            fontOk = true;
            logger.info("PDF 中文字体加载成功：{}", CJK_TTC);
        } catch (Exception e) {
            // 兜底：用 OpenPDF 内置基础字体（中文可能乱码，但不至于生成失败）
            logger.warn("PDF 中文字体加载失败，回退基础字体: {}", e.getMessage());
            cjkTitle = FontFactory.getFont(FontFactory.HELVETICA, 20, Font.BOLD);
            cjkHead = FontFactory.getFont(FontFactory.HELVETICA, 13, Font.BOLD);
            cjkBody = FontFactory.getFont(FontFactory.HELVETICA, 10.5f, Font.NORMAL);
            cjkMono = FontFactory.getFont(FontFactory.COURIER, 9.5f, Font.NORMAL);
            fontOk = false;
        }
    }

    public boolean isFontOk() {
        return fontOk;
    }

    /** 生成单事件 PDF 报告，返回字节数组。 */
    public byte[] buildReport(SecurityEvent e) throws Exception {
        Document document = new Document(com.lowagie.text.PageSize.A4, 36, 36, 42, 40);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter.getInstance(document, baos);
        document.open();

        // 标题
        Paragraph title = new Paragraph("SecAgent 安全事件报告", cjkTitle);
        title.setAlignment(Element.ALIGN_CENTER);
        document.add(title);
        Paragraph sub = new Paragraph("事件编号：" + safe(e.getId()), cjkBody);
        sub.setAlignment(Element.ALIGN_CENTER);
        document.add(sub);
        document.add(new Paragraph(" ", cjkBody));

        // 一、基本信息表
        document.add(section("一、基本信息"));
        PdfPTable info = new PdfPTable(new float[]{1, 2.2f});
        info.setWidthPercentage(100);
        addRow(info, "事件等级", safe(e.getSeverity()));
        addRow(info, "事件类型", safe(e.getType()));
        addRow(info, "来源 IP", safe(e.getSrcIp()));
        addRow(info, "受影响资产", e.getAssets() == null ? "-" : String.join("、", e.getAssets()));
        addRow(info, "发生时间", safe(e.getOccurredAt()));
        addRow(info, "归档时间", safe(e.getArchivedAt()));
        addRow(info, "处置状态", safe(e.getStatus()));
        addRow(info, "处置人", safe(e.getHandler()));
        document.add(info);
        document.add(new Paragraph(" ", cjkBody));

        // 二、事件经过与研判
        document.add(section("二、事件经过与研判"));
        document.add(bodyPara(e.getSummary() == null ? "（无摘要）" : e.getSummary()));

        // 三、IOC
        document.add(section("三、失陷指标（IOC）"));
        PdfPTable ioc = new PdfPTable(new float[]{1, 3});
        ioc.setWidthPercentage(100);
        headerRow(ioc, "类型", "指标值");
        monoRow(ioc, "恶意 IP", safe(e.getSrcIp()));
        monoRow(ioc, "受影响资产", e.getAssets() == null ? "-" : String.join("、", e.getAssets()));
        monoRow(ioc, "事件标题", safe(e.getTitle()));
        document.add(ioc);
        document.add(new Paragraph(" ", cjkBody));

        // 四、处置记录
        document.add(section("四、处置记录"));
        document.add(bodyPara("当前状态：" + safe(e.getStatus()) + "；处置人：" + safe(e.getHandler())
                + "；归档时间：" + safe(e.getArchivedAt()) + "。"));

        // 五、证据原文（等宽）
        document.add(section("五、证据原文快照"));
        Paragraph ev = new Paragraph(safe(e.getRawEvidence()), cjkMono);
        ev.setLeading(14);
        document.add(ev);

        // 结论
        document.add(new Paragraph(" ", cjkBody));
        document.add(section("六、结论"));
        String verdict = "已归档留痕，按处置状态推进闭环。";
        if ("已闭环".equals(e.getStatus())) {
            verdict = "事件已闭环：威胁已处置、证据已留存，纳入历史事件库备查。";
        } else if (e.getSeverity() != null && e.getSeverity().contains("严重")) {
            verdict = "高危事件处置中：建议 24 小时内完成溯源与横向移动排查，确认无残留后门后再闭环。";
        } else {
            verdict = "事件处置中：建议持续观察同源 IP 是否再次发起攻击，必要时升级封禁时长。";
        }
        document.add(bodyPara(verdict));

        document.close();
        return baos.toByteArray();
    }

    // ---------- 小工具 ----------

    private Paragraph section(String text) {
        Paragraph p = new Paragraph(text, cjkHead);
        p.setSpacingBefore(6);
        p.setSpacingAfter(4);
        return p;
    }

    private Paragraph bodyPara(String text) {
        Paragraph p = new Paragraph(text, cjkBody);
        p.setLeading(16);
        return p;
    }

    private void addRow(PdfPTable t, String k, String v) {
        PdfPCell kc = new PdfPCell(new Phrase(k, cjkBody));
        kc.setBackgroundColor(new java.awt.Color(244, 246, 248));
        kc.setPadding(5);
        PdfPCell vc = new PdfPCell(new Phrase(v, cjkBody));
        vc.setPadding(5);
        t.addCell(kc);
        t.addCell(vc);
    }

    private void headerRow(PdfPTable t, String a, String b) {
        PdfPCell ca = new PdfPCell(new Phrase(a, cjkBody));
        ca.setBackgroundColor(new java.awt.Color(230, 244, 242));
        ca.setPadding(5);
        PdfPCell cb = new PdfPCell(new Phrase(b, cjkBody));
        cb.setBackgroundColor(new java.awt.Color(230, 244, 242));
        cb.setPadding(5);
        t.addCell(ca);
        t.addCell(cb);
    }

    private void monoRow(PdfPTable t, String k, String v) {
        PdfPCell kc = new PdfPCell(new Phrase(k, cjkBody));
        kc.setPadding(5);
        PdfPCell vc = new PdfPCell(new Phrase(v, cjkMono));
        vc.setPadding(5);
        t.addCell(kc);
        t.addCell(vc);
    }

    private static String safe(String s) {
        return s == null ? "-" : s;
    }
}
