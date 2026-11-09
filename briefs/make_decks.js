// Build one DRAFT evidence-brief deck per organisation from briefs_out/data/*.json (see make_data.py).
// Usage: PPTX_SKILL=<skill dir> node briefs/make_decks.js briefs_out
// Neutral styling on purpose: no employer branding, no risk score, no sales framing.
const pptxgen = require("pptxgenjs");
const fs = require("fs");
const path = require("path");
const { applyTheme } = require(path.join(process.env.PPTX_SKILL, "scripts/apply_theme.js"));

const THEME = {
  name: "Evidence Brief",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "1B2A2F", lt1: "FFFFFF", dk2: "0F766E", lt2: "EEF2F1",
    accent1: "B45309", accent2: "0F766E", accent3: "64748B", accent4: "9A3412",
    accent5: "3F6212", accent6: "475569", hlink: "0F766E", folHlink: "64748B",
  },
};
const HEX = { ink: "1B2A2F", teal: "0F766E", mist: "EEF2F1", line: "CBD5D1", slate: "64748B", amber: "B45309", white: "FFFFFF" };
const FOOTER = "DRAFT – for internal review – not for distribution. Observations from an automated check: potential issues, not legal findings.";
const VERDICT_SHORT = {
  reject_ignored: "Reject ignored", fires_before_choice: "Fires before any choice", blocked_until_consent: "Blocked until consent",
  no_adtech_observed: "None observed", no_consent_control_found: "No control found", "": "Not tested",
};

function nice(list) { return list.length <= 2 ? list.join(" and ") : list.slice(0, -1).join(", ") + " and " + list[list.length - 1]; }

async function build(d, outFile) {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  pres.title = `${d.domain} - draft evidence brief`;
  pres.author = "Draft - unreviewed";
  const C = pres.SchemeColor;

  const footerObj = (color) => ({ text: { text: FOOTER, options: { x: 0.6, y: 7.05, w: 11.4, h: 0.3, fontSize: 10, color, isTextBox: true, margin: 0 } } });
  pres.defineSlideMaster({
    title: "TITLE", background: { color: HEX.ink },
    objects: [
      footerObj(C.background2),
      { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 1.9, w: 11.7, h: 1.7, fontSize: 40, bold: true, color: C.background1, valign: "bottom", align: "left", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "sub", type: "body", x: 0.8, y: 3.8, w: 11.7, h: 0.9, fontSize: 20, color: C.background2, valign: "top", margin: 0 }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "CONTENT", background: { color: HEX.white },
    objects: [
      footerObj(C.accent3),
      { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 12.1, h: 0.9, fontSize: 30, bold: true, color: C.text1, valign: "middle", align: "left", margin: 0 }, text: "" } },
    ],
    slideNumber: { x: 12.3, y: 7.05, w: 0.5, h: 0.3, fontSize: 10, color: HEX.slate },
  });

  const notes = (s, t) => s.addNotes(t);
  const method = `Method: one automated pass on ${d.scanned_at} using ${d.tool}: fresh Chromium context, no consent given, robots.txt honoured, homepage + up to 3 likely-health pages + privacy policy; a second and third pass clicked Reject and Accept where a control could be found (no forms submitted). Requests were matched to vendor signatures. Nothing here has been verified with the organisation.`;

  // 1. Title
  pres.addSection({ title: "Brief" });
  let s = pres.addSlide({ masterName: "TITLE", sectionTitle: "Brief" });
  s.addText(d.domain, { placeholder: "title" });
  s.addText("Observations from an automated pre-consent website check", { placeholder: "sub" });
  s.addText([
    { text: `Sector label: ${d.sector}`, options: { breakLine: true } },
    { text: `Scan: ${d.scanned_at} · ${d.n_pages} pages visited · ${d.tool}`, options: { breakLine: true } },
    { text: "Potential issues for the organisation to verify – not legal findings" },
  ], { x: 0.8, y: 5.0, w: 11.7, h: 1.2, fontSize: 14, color: C.background2, isTextBox: true, margin: 0, paraSpaceAfter: 4 });
  notes(s, method);

  // 2. Summary
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("What the check observed", { placeholder: "title" });
  const cards = [
    [String(d.adtech_vendors.length), "advertising or session-replay vendors made requests before any interaction"],
    [`${d.n_health_pages_with_adtech} of ${d.n_health_pages}`, "health-related pages visited had advertising or replay requests"],
    [VERDICT_SHORT[d.consent_verdict] || "Not tested", "behaviour when a Reject / Accept control was used"],
  ];
  cards.forEach(([big, label], i) => {
    const x = 0.6 + i * 4.1;
    s.addShape(pres.ShapeType.roundRect, { x, y: 1.5, w: 3.9, h: 1.9, fill: { color: C.background2 }, line: { color: C.background2 }, rectRadius: 0.1, objectName: `Card ${i + 1}` });
    s.addText(big, { x: x + 0.2, y: 1.6, w: 3.5, h: 0.9, fontSize: big.length > 12 ? 24 : 38, bold: true, color: C.accent2, fontFace: "Cambria", valign: "middle", isTextBox: true, margin: 0, objectName: `Card ${i + 1} value` });
    s.addText(label, { x: x + 0.2, y: 2.5, w: 3.5, h: 0.8, fontSize: 12, color: C.text1, valign: "top", isTextBox: true, margin: 0, objectName: `Card ${i + 1} label` });
  });
  const urlVendors = [...new Set(d.health_pages.flatMap((p) => p.url_sent_to))];
  const bullets = [];
  if (d.adtech_vendors.length) bullets.push(`Requests to ${nice(d.adtech_vendors)} were made as soon as pages loaded, before any consent control was used.`);
  if (urlVendors.length) bullets.push(`On health-related pages, the page URL appeared in requests to ${nice(urlVendors)}.`);
  if (d.meta_dl.origin_only > 0 && d.meta_dl.with_path === 0) bullets.push("Meta Pixel requests on inner pages carried only the site address, not the page path, in the document-location parameter.");
  if (d.adv_contact.length) bullets.push(`Meta advanced matching sent hashed contact-detail field(s): ${d.adv_contact.join(", ")}.`);
  bullets.push(d.cmps.length ? `A cookie banner or notice was detected (${d.cmps.join(", ")}).` : "No cookie banner or consent platform was detected.");
  s.addText(bullets.slice(0, 6).map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })),
    { x: 0.6, y: 3.65, w: 12.1, h: 3.2, fontSize: 15, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 8 });
  notes(s, method + (d.undisclosed.length ? ` Privacy page keyword check (shallow; separate cookie statements are not read): the linked privacy page did not name ${nice(d.undisclosed)}. Verify against the organisation's full policy set before saying anything about disclosure.` : ""));

  // 3. What fired, where
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("What fired, and where", { placeholder: "title" });
  const head = ["Vendor", "Type", "Identifier", "Events seen", "Pages seen on", "Page URL in request"].map((t) => ({
    text: t, options: { bold: true, color: HEX.white, fill: { color: HEX.ink }, fontSize: 12 } }));
  const rows = [head].concat(d.vendors.slice(0, 9).map((v) => [v.vendor, v.category, v.ids, v.events, `${v.pages}`, v.url_in_request]
    .map((t) => ({ text: String(t), options: { fontSize: 11, color: HEX.ink } }))));
  s.addTable(rows, { x: 0.6, y: 1.5, w: 12.1, colW: [2.4, 1.3, 1.8, 2.3, 2.3, 2.0], border: { type: "solid", pt: 0.75, color: HEX.line }, valign: "middle", margin: [0.05, 0.08, 0.05, 0.08], autoPage: false, objectName: "Vendor table" });
  s.addText("Requests were matched against known vendor address patterns. “Data sent” means a request that transmits data to the vendor, not merely a library download.",
    { x: 0.6, y: 6.45, w: 12.1, h: 0.45, fontSize: 11, color: C.accent3, isTextBox: true, margin: 0 });
  notes(s, method);

  // 4. Health-related pages
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("Health-related pages visited", { placeholder: "title" });
  if (d.health_pages.length) {
    const h2 = ["Page", "Forms", "Advertising / replay requests seen", "Page URL sent to"].map((t) => ({ text: t, options: { bold: true, color: HEX.white, fill: { color: HEX.ink }, fontSize: 12 } }));
    const r2 = [h2].concat(d.health_pages.slice(0, 8).map((p) => [p.path.slice(0, 60), String(p.forms), p.adtech.join(", ") || "None observed", p.url_sent_to.join(", ") || "Not observed"]
      .map((t) => ({ text: t, options: { fontSize: 11, color: HEX.ink } }))));
    s.addTable(r2, { x: 0.6, y: 1.5, w: 12.1, colW: [4.4, 0.8, 4.4, 2.5], border: { type: "solid", pt: 0.75, color: HEX.line }, valign: "middle", margin: [0.05, 0.08, 0.05, 0.08], autoPage: false, objectName: "Health pages table" });
  } else {
    s.addText("No pages matching health-related URL keywords were visited in this scan.", { x: 0.6, y: 1.6, w: 12.1, h: 0.6, fontSize: 16, color: C.text1, isTextBox: true, margin: 0 });
  }
  s.addText("“Health-related” means the page address matches health keywords (for example a condition, treatment or booking page). It does not show that the page reveals information about an individual’s health.",
    { x: 0.6, y: Math.min(6.2, 1.5 + (Math.min(d.health_pages.length, 8) + 1) * 0.42 + 0.3), w: 12.1, h: 0.7, fontSize: 12, color: C.accent3, isTextBox: true, margin: 0 });
  notes(s, method);

  // 5. Screenshots
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("What a visitor saw on arrival", { placeholder: "title" });
  const shots = d.shots.slice(0, 2);
  if (shots.length === 2) {
    shots.forEach((sh, i) => {
      const x = 0.6 + i * 6.15;
      s.addImage({ path: sh.file, x, y: 1.5, w: 5.95, h: 3.7, altText: `Screenshot of ${d.domain}${sh.path}`, objectName: `Screenshot ${i + 1}` });
      s.addText(`${sh.role === "home" ? "Homepage" : "Health-related page"}: ${sh.path.slice(0, 55)}`, { x, y: 5.3, w: 5.95, h: 0.35, fontSize: 11, color: C.accent3, isTextBox: true, margin: 0 });
    });
    s.addText(d.cmps.length ? `Banner detected: ${d.cmps.join(", ")}. Screenshots were taken at page load, before any consent control was used.` : "No banner detected. Screenshots were taken at page load, before any consent control was used.",
      { x: 0.6, y: 5.8, w: 12.1, h: 0.8, fontSize: 14, color: C.text1, isTextBox: true, margin: 0 });
  } else if (shots.length === 1) {
    s.addImage({ path: shots[0].file, x: 0.6, y: 1.5, w: 7.6, h: 4.73, altText: `Screenshot of ${d.domain}`, objectName: "Screenshot" });
    s.addText([
      { text: "Taken at page load, before any consent control was used.", options: { breakLine: true } },
      { text: d.cmps.length ? `Banner detected: ${d.cmps.join(", ")}.` : "No banner detected." },
    ], { x: 8.6, y: 1.5, w: 4.1, h: 2.2, fontSize: 14, color: C.text1, isTextBox: true, margin: 0, paraSpaceAfter: 8 });
  } else {
    s.addText("No screenshots were captured.", { x: 0.6, y: 1.6, w: 12.1, h: 0.6, fontSize: 16, color: C.text1, isTextBox: true, margin: 0 });
  }
  notes(s, method);

  // 6. Consent test
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("Consent behaviour when tested", { placeholder: "title" });
  if (d.consent_modes.length) {
    const h3 = ["Mode", "Control clicked", "Advertising / replay observed"].map((t) => ({ text: t, options: { bold: true, color: HEX.white, fill: { color: HEX.ink }, fontSize: 12 } }));
    const r3 = [h3].concat(d.consent_modes.map((m) => [m.mode, m.clicked, m.adtech].map((t) => ({ text: t, options: { fontSize: 12, color: HEX.ink } }))));
    s.addTable(r3, { x: 0.6, y: 1.5, w: 12.1, colW: [3.0, 2.6, 6.5], border: { type: "solid", pt: 0.75, color: HEX.line }, valign: "middle", margin: [0.06, 0.1, 0.06, 0.1], autoPage: false, objectName: "Consent table" });
  }
  const base = (d.consent_modes.find((m) => m.mode === "No interaction") || {}).adtech;
  const cnotes = [`Result: ${d.consent_verdict_label}.`];
  if (base && base !== "None observed") cnotes.push(`With no interaction, requests were made to: ${base}.`);
  if (d.consent_verdict === "no_consent_control_found" && d.cmps.length) cnotes.push(`A banner or notice was detected (${d.cmps.join(", ")}) but no recognisable Accept or Reject button was found: it may be notice-only, or an unusual design. See the screenshot.`);
  d.consent_notes.filter((n) => !/^Could not find or click|^Ad-tech\/replay fired before any choice|^A cookie banner\/notice was detected/.test(n)).slice(0, 2).forEach((n) => cnotes.push(n));
  cnotes.push("A banner or notice can bear on notice (APP 5) but is not, by itself, consent for collecting sensitive information (APP 3.3).");
  s.addText(cnotes.map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })),
    { x: 0.6, y: 3.9, w: 12.1, h: 2.9, fontSize: 14, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 8 });
  notes(s, method + " Control-finding is automated and may miss banners with unusual designs; check the screenshots.");

  // 7. Context
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("Context: the OAIC’s Monash IVF determination", { placeholder: "title" });
  s.addText("What the Commissioner found", { x: 0.6, y: 1.4, w: 6.0, h: 0.4, fontSize: 18, bold: true, color: C.accent2, fontFace: "Cambria", isTextBox: true, margin: 0 });
  const left = [
    "[2026] AICmr 40 (11 June 2026): breaches of APP 3.3, 5.1 and 7.1 over 30 July 2012 – 9 December 2024 [1].",
    "Monash was covered as a health service provider [29]; engagement with a health provider’s website was treated as revealing or allowing inference about health [83].",
    "The organisation that commissioned and controlled the pixels “collected” the data [55].",
    "Notice was expected when a visitor first arrives, for example a banner or pop-up [113, 115]; consent mode was noted as available [104].",
  ];
  s.addText(left.map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 0.6, y: 1.85, w: 6.0, h: 4.9, fontSize: 15, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 8 });
  s.addText("How this check relates", { x: 7.0, y: 1.4, w: 5.7, h: 0.4, fontSize: 18, bold: true, color: C.accent2, fontFace: "Cambria", isTextBox: true, margin: 0 });
  const right = [
    "Observed: pixel and analytics requests at page load, before any consent control was used.",
    "Not observed: retargeting, audience uploads, whether information is personal or sensitive, and whether notice or consent was adequate.",
    "The ruling concerns one respondent, makes no pixel-by-pixel finding, and the Commissioner calls the identifiability reasoning potentially novel [74]. Review rights exist.",
    "This brief does not say the organisation has breached the Privacy Act.",
  ];
  s.addText(right.map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 7.0, y: 1.85, w: 5.7, h: 4.9, fontSize: 15, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 8 });
  notes(s, "Paragraph references are to Commissioner Initiated Investigation into Monash IVF Pty Ltd (Privacy) [2026] AICmr 40. Verify against the primary text before relying on them.");

  // 8. Suggested checks
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("Checks the organisation may wish to make", { placeholder: "title" });
  const checks = [
    "Inventory every tag on health-related pages, including those loaded through a tag manager.",
    "Confirm whether advertising tags can fire before a visitor makes a choice, and whether a consent mode or blocking mechanism is in place.",
    "Review what each pixel is configured to send (page URLs, form events, advanced matching).",
    "Check whether retargeting or audience uploads use data from health-related pages or forms.",
    "Compare the notice given on arrival, and the privacy policy, against what the tags actually do.",
    "Consider a privacy impact assessment for any tracking on health-related pages.",
  ];
  s.addText(checks.map((t, i, a) => ({ text: t, options: { bullet: true, breakLine: i < a.length - 1 } })), { x: 0.6, y: 1.5, w: 12.1, h: 4.9, fontSize: 16, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 10 });
  notes(s, "Neutral checklist; not advice specific to the organisation's legal position.");

  // 9. Optional next step
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Brief" });
  s.addText("Possible next step (optional)", { placeholder: "title" });
  s.addText([
    { text: "We can share the full evidence log and screenshots and would welcome the organisation’s own view of what these tags do.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true } },
    { text: "[Sender name, role and contact – to be completed after internal approval]", options: { color: HEX.amber, italic: true } },
  ], { x: 0.6, y: 1.6, w: 12.1, h: 2.0, fontSize: 18, color: C.text1, valign: "top", isTextBox: true, margin: 0 });
  s.addText("Remove this slide if the briefing is a notification only. Do not send until legal and risk review is complete.", { x: 0.6, y: 5.9, w: 12.1, h: 0.6, fontSize: 13, color: C.accent3, italic: true, isTextBox: true, margin: 0 });

  // Appendix: evidence log
  pres.addSection({ title: "Appendix" });
  const per = 12, pagesN = Math.max(1, Math.ceil(d.log.length / per));
  for (let p = 0; p < pagesN; p++) {
    s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Appendix" });
    s.addText(`Evidence log (${p + 1} of ${pagesN})`, { placeholder: "title" });
    const h4 = ["Vendor", "Page", "Events", "Identifier", "URL sent", "×"].map((t) => ({ text: t, options: { bold: true, color: HEX.white, fill: { color: HEX.ink }, fontSize: 11 } }));
    const r4 = [h4].concat(d.log.slice(p * per, p * per + per).map((row) => row.map((t) => ({ text: t, options: { fontSize: 10, color: HEX.ink } }))));
    s.addTable(r4, { x: 0.6, y: 1.4, w: 12.1, colW: [3.0, 3.6, 2.0, 1.9, 1.0, 0.6], border: { type: "solid", pt: 0.5, color: HEX.line }, valign: "middle", margin: [0.03, 0.06, 0.03, 0.06], autoPage: false, objectName: "Evidence log" });
    s.addText(`Showing data-sending requests only (${d.log.length} of ${d.log_total} vendor/page entries). The complete request records are in the scan results file.`,
      { x: 0.6, y: 6.5, w: 12.1, h: 0.4, fontSize: 11, color: C.accent3, isTextBox: true, margin: 0 });
    notes(s, method);
  }

  await pres.writeFile({ fileName: outFile });
  await applyTheme(outFile, THEME);
}

(async () => {
  const dir = process.argv[2];
  const dataDir = path.join(dir, "data");
  for (const f of fs.readdirSync(dataDir).filter((x) => x.endsWith(".json")).sort()) {
    const d = JSON.parse(fs.readFileSync(path.join(dataDir, f), "utf8"));
    const out = path.join(dir, f.replace(".json", "_evidence_brief_DRAFT.pptx"));
    await build(d, out);
    console.log("wrote", out);
  }
})().catch((e) => { console.error(e); process.exit(1); });
