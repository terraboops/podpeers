// Drives a real browser at `podpeers serve` the way a hostile web page would,
// and observes what happens. Two attacks:
//
//  1. DNS rebinding. A page loaded from the attacker's name rebinds that name
//     to 127.0.0.1, then reads http://<name>:<port>/graphql as "same-origin".
//     Chrome's --host-resolver-rules gives the rebound DNS answer; the
//     attacker's first page is served by request interception, as the
//     attacker's server would. Everything after that is the real browser: its
//     fetch, its Host header, its same-origin read.
//  2. A cross-site POST from another origin straight to 127.0.0.1.
//
// Each runs in two browsers. Chrome as shipped may block a public page's
// request to loopback itself (Local Network Access): whatever it does, the
// page must never read capture data. With those checks switched off, standing
// in for a browser that has none, the request must reach podpeers, and
// podpeers' own guard must refuse it. A control from the server's own origin
// must read the capture, so a refusal is the guard and not a broken setup.
//
//   node rebind.mjs PORT
import puppeteer from "puppeteer";

const port = process.argv[2];
const browsers = [
  ["Chrome as shipped", []],
  ["Chrome with its network-access checks off", ["--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests"]],
];
const fails = [];
const ok = msg => console.log("ok    " + msg);
const fail = msg => { console.log("FAIL  " + msg); fails.push(msg); };
const within = (p, ms, v) => Promise.race([p, new Promise(r => setTimeout(() => r(v), ms))]);

// The attacker's page: try to read the capture, report what the page saw.
const attacker = (target, post) => `<!doctype html><script>
window.result = (async () => {
  try {
    const r = await fetch(${JSON.stringify(target)}${post ? `, {method: "POST", headers: {"Content-Type": "text/plain"}, body: '{"query":"{ pods { id } }"}'}` : ""});
    return {read: true, status: r.status, body: (await r.text()).slice(0, 300)};
  } catch (e) { return {read: false, error: String(e)}; }
})();
</script>`;

// Load the attacker's page at `from` and report what the page read and what,
// if anything, the server answered, as the browser's network layer saw it.
async function attack(browser, from, target, post) {
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on("request", req => {
    if (req.isNavigationRequest() && new URL(req.url()).hostname === new URL(from).hostname) {
      return req.respond({ status: 200, contentType: "text/html", body: attacker(target, post) });
    }
    req.continue();
  });
  let server = null, failed = null;
  // The server's status comes from the network layer (CDP), which sees it even
  // when CORS then stops the page from reading the response.
  const cdp = await page.createCDPSession();
  await cdp.send("Network.enable");
  const urls = {};
  cdp.on("Network.requestWillBeSent", e => { urls[e.requestId] = e.request.url; });
  cdp.on("Network.responseReceivedExtraInfo", e => {
    if (urls[e.requestId] && new URL(urls[e.requestId]).pathname === "/graphql") server = e.statusCode;
  });
  page.on("requestfailed", r => { if (new URL(r.url()).pathname === "/graphql") failed = r.failure()?.errorText; });
  await page.goto(from);
  const seen = await within(page.evaluate(() => window.result), 15000, { timeout: true });
  await new Promise(r => setTimeout(r, 200));
  await page.close();
  return { seen, server, failed };
}

const leaked = s => s.read && s.body.includes('"pods"');

for (const [name, extra] of browsers) {
  const opts = {
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--host-resolver-rules=MAP rebind.test 127.0.0.1, MAP evil.test 127.0.0.1", ...extra],
  };
  if (process.env.PUPPETEER_EXECUTABLE_PATH) opts.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
  const browser = await puppeteer.launch(opts);
  const strict = extra.length > 0; // must reach podpeers and be refused by it
  try {
    const rb = await attack(browser, `http://rebind.test:${port}/`, "/graphql?query=" + encodeURIComponent("{ pods { id } }"), false);
    const what = rb.server ? `podpeers answered ${rb.server}` : `the browser blocked it (${rb.failed})`;
    if (leaked(rb.seen) || (strict && rb.server !== 421) || (!rb.server && !rb.failed)) {
      fail(`${name}: DNS rebinding: ${what}; the page saw ${JSON.stringify(rb.seen)}`);
    } else {
      ok(`${name}: DNS rebinding as Host rebind.test:${port}: ${what}; the page read no capture data`);
    }

    const xs = await attack(browser, "http://evil.test:9/", `http://127.0.0.1:${port}/graphql`, true);
    const how = xs.server ? `podpeers answered ${xs.server}` : `the browser blocked it (${xs.failed})`;
    if (leaked(xs.seen) || (strict && xs.server !== 403) || (!xs.server && !xs.failed)) {
      fail(`${name}: cross-site POST: ${how}; the page saw ${JSON.stringify(xs.seen)}`);
    } else {
      ok(`${name}: cross-site POST from http://evil.test: ${how}; the page read nothing`);
    }

    // Control: from the server's own origin, the same read works.
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${port}/`);
    const own = await page.evaluate(async () => {
      const resp = await fetch("/graphql?query=" + encodeURIComponent("{ pods { id } }"));
      return { status: resp.status, body: (await resp.text()).slice(0, 300) };
    });
    if (own.status === 200 && own.body.includes('"pods"')) ok(`${name}: control: the server's own page reads the capture (200)`);
    else fail(`${name}: control: own origin got ${JSON.stringify(own)}`);
  } finally {
    await browser.close();
  }
}
console.log(fails.length ? `rebind check: ${fails.length} failure(s)` : "rebind check: ok");
process.exit(fails.length ? 1 : 0);
