// Drives the web UI the way a reader does, in headless Chrome: search for a
// peer, read the detail panel, switch views, run a query in the GraphQL
// console. Fails on any page error, on a peer shown in the wrong group, or on
// a console answer that differs from `podpeers query` on the same capture.
//
//   node check.mjs URL QUERY WANT_JSON [SCREENSHOT_DIR]
import puppeteer from "puppeteer";

const [url, query, want, shots] = process.argv.slice(2);
const opts = { headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] };
if (process.env.PUPPETEER_EXECUTABLE_PATH) opts.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
const browser = await puppeteer.launch(opts);
const fails = [];
const ok = msg => console.log("ok    " + msg);
const fail = msg => { console.log("FAIL  " + msg); fails.push(msg); };

// Key order is not meaning: compare JSON with sorted keys.
const canon = v => Array.isArray(v) ? v.map(canon)
  : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canon(v[k])])) : v;

try {
  const page = await browser.newPage();
  page.on("pageerror", e => fail("page error: " + e.message));
  page.on("console", m => { if (m.type() === "error") fail("console error: " + m.text()); });
  await page.setViewport({ width: 1400, height: 900 });
  await page.goto(url, { waitUntil: "networkidle0" });

  // Laid out and fitted, the graph is drawn at a readable scale: no smaller
  // than the zoom's own floor (a layout that flies apart is framed at a few
  // percent).
  // The graph's scale, or NaN when it was never fitted (no nodes drawn): a
  // judged failure below, never a crash of this check.
  const scaleOf = t => +(/scale\(([-\d.e]+)\)/.exec(t || "") || [])[1];
  const fitted = scaleOf(await page.$eval("#graph > g", g => g.getAttribute("transform")));
  if (fitted >= 0.2) ok(`the fitted graph is drawn at a readable scale (${fitted.toFixed(2)})`);
  else fail(Number.isNaN(fitted) ? "the graph was never fitted: no nodes were drawn"
    : `the fitted graph is drawn at scale ${fitted}: laid out far too wide to read`);

  // Before anything is selected, the panel lists what the capture could not
  // see: every limit the page carries, as written.
  const [carried, shown] = await page.evaluate(() =>
    [DATA.limits || [], [...document.querySelectorAll("#detail details.limits li")].map(l => l.textContent)]);
  if (carried.length > 0 && JSON.stringify(carried) === JSON.stringify(shown)) ok(`the idle panel lists the capture's ${carried.length} limits`);
  else fail(`the idle panel should list the capture's limits: the page carries ${JSON.stringify(carried)}, the panel shows ${JSON.stringify(shown)}`);

  // What the detail panel says about the first match for a search.
  const lookup = async q => {
    await page.click("#find", { clickCount: 3 });
    await page.keyboard.type(q);
    return page.$eval("#detail", d => ({
      label: d.querySelector("h2")?.textContent,
      pills: [...d.querySelectorAll(":scope > span.pill")].slice(0, 2).map(s => s.textContent),
    }));
  };
  // [search, label, kind, group]
  const expect = [
    ["node-a", "node-a", "node", "(cluster nodes)"],            // a node, by its IP
    ["node-b", "node-b", "node", "(cluster nodes)"],            // a node, on its pod network
    ["203.0.113.9", "203.0.113.9", "external", "(outside the cluster)"],
  ];
  for (const view of ["v-wl", "v-pod"]) {
    await page.click("#" + view);
    for (const [q, label, kind, group] of expect) {
      const d = await lookup(q);
      if (d.label === label && d.pills[0] === kind && d.pills[1] === group) ok(`${view}: ${q} is a ${kind} in ${group}`);
      else fail(`${view}: ${q}: want ${label} / ${kind} / ${group}, the panel says ${JSON.stringify(d)}`);
    }
    if (shots) await page.screenshot({ path: `${shots}/ui-${view}.png` });
  }

  // Services: drawn as squares in the pod view; in the workload view each
  // folds into the workload behind it, if it has one: ext has no selector,
  // so it backs no pod and stays a service.
  const squares = () => page.$$eval("#graph rect.shape", r => r.length);
  const panel = () => page.$eval("#detail", d => d.textContent);
  await page.click("#v-pod");
  if ((await squares()) === 3) ok("v-pod: all three services are drawn, as services");
  else fail(`v-pod: want 3 services drawn as squares, got ${await squares()}`);
  await page.click("#v-wl");
  if ((await squares()) === 1) ok("v-wl: each service with pods folds into the workload behind it; ext, with no selector, stays");
  else fail(`v-wl: want only ext (no selector) left as a service, got ${await squares()}`);
  // The panel: listening ports, member pods counted once however many flows
  // name them, and an honest "none observed" for a pod nobody talked to.
  await lookup("web");
  let text = await panel();
  // web and web-b are one Deployment, frontend: one node, named for the
  // workload, of kind Deployment, with both pods counted once each.
  const fe = await page.$eval("#detail", d => ({ h2: d.querySelector("h2")?.textContent, kind: d.querySelector(":scope > span.pill")?.textContent }));
  if (fe.h2 === "frontend" && fe.kind === "Deployment" && text.includes("listening") && text.includes("tcp/8080") && text.includes("pods (2)"))
    ok("v-wl: web's two replicas are one Deployment, frontend, listening on tcp/8080");
  else fail(`v-wl: web should fold into Deployment frontend, listening tcp/8080, pods (2): ${JSON.stringify(fe)} ${text.slice(0, 300)}`);
  const captions = await page.$$eval("#graph g.n", gs => gs.map(g => g.textContent));
  const caption = captions.find(t => t.startsWith("frontend")) || "";
  if (caption.includes("×2 pods") && !captions.some(t => t.includes("×1 pods"))) ok("v-wl: the frontend node says it stands for two pods, and no single-pod node says anything");
  else fail(`v-wl: only frontend should carry a pod count (×2 pods): ${JSON.stringify(captions)}`);
  // web's own side never connected to api (failed connects), but api saw web
  // connect: one flow, and since one side saw it established, it is open.
  const toApi = await page.$$eval("#detail tr", rows => rows.map(r => [...r.cells].map(c => c.textContent))
    .filter(c => c[0] && c[0].startsWith("api")).map(c => c[1] + " " + c[2]));
  // 9000/tcp maps to target 9000; the Service's 9000/udp (target 9999) is
  // another protocol and must not be picked.
  if (toApi.length === 1 && toApi[0] === "tcp/9000 open") ok("v-wl: web -> api is one open flow on 9000: one side saw it established, and the port mapped by protocol");
  else fail(`v-wl: web -> api should be one open flow on 9000, the panel says ${JSON.stringify(toApi)}`);
  // Where web connects, folded: api (only its own selector's pods, in its
  // own namespace) and ext. Nothing else in shop.
  const outRows = await page.$$eval("#detail table", ts => ts.length < 2 ? [] : [...ts[1].rows].slice(1).map(r => r.cells[0].textContent.split(" ")[0]));
  if (JSON.stringify(outRows.sort()) === '["api","ext"]') ok("v-wl: web connects to api and ext, and nothing else");
  else fail(`v-wl: web's outbound should be api and ext only, the panel says ${JSON.stringify(outRows)}`);
  // The selection survives a switch of view.
  await page.click("#v-pod");
  if ((await page.$eval("#detail", d => d.querySelector("h2")?.textContent)) === "web") ok("the selection carries across views");
  else fail(`switching view lost the selection: ${(await panel()).slice(0, 120)}`);
  // Selecting web (now in the pod view) lights its flows only, and dims
  // what it does not talk to.
  const hl = await page.$$eval("#graph path.flow", ps => [ps.filter(p => p.classList.contains("hl")).length, ps.length]);
  const dims = await page.$$eval("#graph g.n", gs => Object.fromEntries(gs.map(g => [g.textContent, g.classList.contains("dim")])));
  const dimOf = name => Object.entries(dims).find(([t]) => t.startsWith(name))?.[1];
  if (hl[0] > 0 && hl[0] < hl[1] && dimOf("idle") === true && dimOf("gateway") === false) ok("v-pod: selecting web lights its flows and dims the rest");
  else fail(`v-pod: selecting web: ${hl[0]} of ${hl[1]} flows lit, idle dim ${dimOf("idle")}, gateway dim ${dimOf("gateway")}`);
  // A pod that was not observed is drawn hollow.
  const fills = await page.$$eval("#graph g.n", gs => Object.fromEntries(gs.map(g => [g.textContent, g.querySelector(".shape")?.getAttribute("fill")])));
  const fillOf = name => Object.entries(fills).find(([t]) => t.startsWith(name))?.[1];
  if (fillOf("batch") === "var(--panel)" && fillOf("web") !== "var(--panel)") ok("v-pod: an unobserved pod is drawn hollow");
  else fail(`v-pod: batch (not observed) should be hollow and web not: ${fillOf("batch")} / ${fillOf("web")}`);
  // Search finds a pod by its address, and the header counts by status.
  if ((await lookup("192.0.2.11")).label === "web") ok("v-pod: search by a pod's address finds it");
  else fail("v-pod: searching 192.0.2.11 should find web");
  const summary = await page.$eval("#summary", s => s.textContent);
  if (summary.includes("5 pods observed, 1 failed, 1 skipped")) ok("the header counts pods by status");
  else fail(`the header should say 5 pods observed, 1 failed, 1 skipped: ${summary}`);
  await lookup("idle");
  text = await panel();
  if ((text.match(/none observed/g) || []).length === 2) ok("v-pod: an idle pod says none observed, in and out");
  else fail(`v-pod: idle should say none observed twice: ${text.slice(0, 300)}`);

  // A node seen at two addresses is still one node, in either view.
  for (const view of ["v-wl", "v-pod"]) {
    await page.click("#" + view);
    const nodeA = await page.$$eval("#graph g.n", gs => gs.filter(g => g.textContent.startsWith("node-a")).length);
    if (nodeA === 1) ok(`${view}: node-a, seen at two addresses, is one node`);
    else fail(`${view}: node-a should be one node, got ${nodeA}`);
  }
  // web's panel, pod view: the other end of each flow, its namespace when it
  // differs, and what state each flow ended in.
  await lookup("192.0.2.11");
  const tables = await page.$$eval("#detail table", ts => ts.map(t => ({
    head: t.rows[0].cells[0].textContent,
    rows: [...t.rows].slice(1).map(r => [...r.cells].map(c => c.textContent)),
  })));
  const [inT, outT] = tables;
  if (inT?.head === "from" && outT?.head === "to") ok("v-pod: the panel's tables say from and to");
  else fail(`v-pod: the panel's tables should be headed from / to: ${JSON.stringify(tables.map(t => t.head))}`);
  if (inT?.rows.some(r => r[0] === "gateway edge")) ok("v-pod: web's inbound names gateway, and its other namespace");
  else fail(`v-pod: web's inbound should list gateway, tagged edge: ${JSON.stringify(inT?.rows)}`);
  if (outT?.rows.some(r => r[0].startsWith("api") && r[2] === "never connected")) ok("v-pod: web's own attempt at the api service says never connected");
  else fail(`v-pod: web -> svc api should say never connected: ${JSON.stringify(outT?.rows)}`);
  // Flow lines: one attempted, two closed, each says so; lit ones use the lit arrow.
  const lines = await page.$$eval("#graph path.flow", ps => ps.map(p => ({ cls: p.getAttribute("class"), title: p.querySelector("title")?.textContent || "", marker: p.getAttribute("marker-end") })));
  const attempted = lines.filter(l => l.cls.includes("attempted")), closed = lines.filter(l => l.cls.includes("closed"));
  const openOnes = lines.filter(l => !l.cls.includes("attempted") && !l.cls.includes("closed"));
  if (attempted.length === 1 && closed.length === 2 && attempted[0].title.includes("(never connected)") && closed.every(l => l.title.includes("(closed during window)"))
      && openOnes.length > 0 && openOnes.every(l => !l.title.includes("(")))
    ok("v-pod: the one attempted and the two closed flows are drawn and titled so, and open ones are not");
  else fail(`v-pod: want 1 attempted and 2 closed flows, titled so: ${JSON.stringify(attempted)} ${JSON.stringify(closed)}`);
  const lit = lines.filter(l => l.cls.includes("hl"));
  if (lit.length > 0 && lit.every(l => l.marker === "url(#arrow-hl)")) ok("v-pod: lit flows carry the lit arrow");
  else fail(`v-pod: lit flows should end in the lit arrow: ${JSON.stringify(lit)}`);
  // The selection carries from pods to workloads too.
  await page.click("#v-wl");
  if ((await page.$eval("#detail", d => d.querySelector("h2")?.textContent)) === "frontend") ok("the selection carries from a pod to its workload");
  else fail("switching to workloads should select frontend, web's workload");
  // A failed or skipped pod says so, with the reason.
  await page.click("#v-pod");
  for (const [q, want] of [["broken", "failed: debug container did not start"], ["queued", "skipped: pod phase is Pending, not Running"]]) {
    await lookup(q);
    const st = await page.$eval("#detail", d => [...d.querySelectorAll("div span")].map(s => [s.className, s.textContent]));
    const bad = q === "broken";
    if (st.some(([cls, t]) => t === want && (cls === "bad") === bad)) ok(`v-pod: ${q} says ${want}${bad ? ", marked bad" : ""}`);
    else fail(`v-pod: ${q} should say ${want}: ${JSON.stringify(st)}`);
  }

  // Laid out, no two nodes overlap: each sits clear of the others' shapes.
  for (const view of ["v-wl", "v-pod"]) {
    await page.click("#" + view);
    const clash = await page.$$eval("#graph g.n", gs => {
      const ns = gs.map(g => {
        const m = /translate\(([-\d.e]+),([-\d.e]+)\)/.exec(g.getAttribute("transform") || "");
        const s = g.querySelector(".shape"), r = s.tagName === "rect" ? +s.getAttribute("width") / 2 : +s.getAttribute("r");
        return { t: g.textContent.slice(0, 20), x: m ? +m[1] : NaN, y: m ? +m[2] : NaN, r };
      });
      const lost = ns.find(n => !Number.isFinite(n.x) || !Number.isFinite(n.y));
      if (lost) return `${lost.t} has no position (${lost.x}, ${lost.y})`;
      for (let i = 0; i < ns.length; i++) for (let j = i + 1; j < ns.length; j++) {
        const a = ns[i], b = ns[j];
        if (Math.hypot(a.x - b.x, a.y - b.y) < a.r + b.r) return `${a.t} and ${b.t}`;
      }
      return "";
    });
    if (!clash) ok(`${view}: no two nodes overlap`);
    else fail(`${view}: nodes overlap: ${clash}`);
  }

  // The wheel zooms: up in, down out, and a sideways scroll not at all.
  const zoom = async (dx, dy) => {
    const box = await page.$eval("#graph", g => { const r = g.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; });
    await page.mouse.move(box.x, box.y);
    const before = await page.$eval("#graph > g", g => g.getAttribute("transform"));
    await page.mouse.wheel({ deltaX: dx, deltaY: dy });
    await new Promise(r => setTimeout(r, 100));
    const after = await page.$eval("#graph > g", g => g.getAttribute("transform"));
    return scaleOf(after) / scaleOf(before);
  };
  const [zin, zout, side] = [await zoom(0, -100), await zoom(0, 100), await zoom(100, 0)];
  if (zin > 1 && zout < 1 && side === 1) ok("the wheel zooms in and out, and a sideways scroll leaves the zoom alone");
  else fail(`wheel zoom factors: up ${zin}, down ${zout}, sideways ${side}`);

  // The GraphQL console answers from the same data as `podpeers query`.
  if (!(await page.$eval("#console", c => !c.hidden))) fail("GraphQL console is hidden on the served page");
  await page.$eval("#q", el => { el.value = ""; });
  await page.type("#q", query);
  await page.click("#run");
  // The console shows a placeholder while the request runs; wait for JSON.
  await page.waitForFunction(() => document.querySelector("#out").textContent.trim().startsWith("{"), { timeout: 10000 });
  const got = await page.$eval("#out", o => o.textContent);
  let same = false;
  try { same = JSON.stringify(canon(JSON.parse(got))) === JSON.stringify(canon(JSON.parse(want))); } catch (e) { fail("console answer is not JSON: " + got.slice(0, 200)); }
  if (same) ok("GraphQL console answer equals `podpeers query`");
  else fail(`console answer differs from podpeers query:\n  console: ${got.slice(0, 300)}\n  cli:     ${want.slice(0, 300)}`);
  if (shots) await page.screenshot({ path: `${shots}/ui-console.png` });
} finally {
  await browser.close();
}
console.log(fails.length ? `ui check: ${fails.length} failure(s)` : "ui check: ok");
process.exit(fails.length ? 1 : 0);
