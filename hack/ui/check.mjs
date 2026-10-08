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
