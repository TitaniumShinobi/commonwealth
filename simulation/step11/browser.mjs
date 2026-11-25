import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [chrome, root, run] = process.argv.slice(2);
const profile = join(root, "chrome-profile");
const launchPage = "data:text/html," + encodeURIComponent(
  '<input id="address" type="url"><button id="go">Go</button><script>document.querySelector("#go").onclick=()=>location.assign(document.querySelector("#address").value)</script>');
const browser = spawn(chrome, ["--headless", "--no-sandbox", "--no-proxy-server",
  "--disable-background-networking", "--disable-dev-shm-usage", "--disable-quic", "--no-first-run",
  "--remote-debugging-port=0", "--user-data-dir=" + profile, "about:blank"],
  {stdio: ["ignore", "ignore", "inherit"]});
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label) {
  for (let i = 0; i < 400; i++) {
    let result;
    try { result = await fn(); } catch {}
    if (result) return result;
    await wait(40);
  }
  throw Error(label);
}
const evidence = {run_id: run, trials: {}};
try {
  const port = await until(async () =>
    (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0], "debug_port_unavailable");
  const page = await until(async () =>
    (await (await fetch("http://127.0.0.1:" + port + "/json/list")).json()).find(x => x.type === "page"),
    "browser_target_unavailable");
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, {once: true});
    socket.addEventListener("error", reject, {once: true});
  });
  const pending = new Map();
  const responses = [];
  let id = 0;
  socket.addEventListener("message", event => {
    const data = JSON.parse(event.data);
    if (data.method === "Network.responseReceived") responses.push(data.params.response);
    if (pending.has(data.id)) {
      pending.get(data.id)(data);
      pending.delete(data.id);
    }
  });
  function send(method, params = {}) {
    return new Promise(resolve => {
      pending.set(++id, resolve);
      socket.send(JSON.stringify({id, method, params}));
    });
  }
  async function value(expression) {
    const result = await send("Runtime.evaluate", {expression, returnByValue: true, awaitPromise: true});
    return result.result?.result?.value;
  }
  async function click(selector) {
    const pos = await until(() => value("(()=>{const e=document.querySelector(" + JSON.stringify(selector) +
      ");if(!e)return null;const r=e.getBoundingClientRect();return [r.x+r.width/2,r.y+r.height/2]})()"), selector);
    for (const type of ["mousePressed", "mouseReleased"])
      await send("Input.dispatchMouseEvent", {type, x: pos[0], y: pos[1], button: "left", clickCount: 1});
  }
  await send("Network.enable");
  await send("Network.setCacheDisabled", {cacheDisabled: true});
  const wrong = await send("Page.navigate", {url: "https://wrong.lab.example/wrong-name-probe"});
  evidence.wrong_name = {error: wrong.result?.errorText, url: "https://wrong.lab.example/wrong-name-probe"};
  await send("Page.navigate", {url: launchPage});
  await click("#address");
  const destination = "https://lab.example";
  await send("Input.insertText", {text: destination});
  evidence.typed = await value("document.querySelector('#address').value");
  await click("#go");
  await until(() => value("document.querySelector('h1')?.textContent === 'Simulation'"), "typed navigation failed");
  evidence.denied = await value("fetch('/experiment',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({trial:'ideal-0'})}).then(r=>r.status)");
  const session = await send("Network.setCookie", {name: "lab_session",
    value: process.env.CW11_BROWSER_SESSION, url: destination, secure: true, httpOnly: true, sameSite: "Strict"});
  if (!session.result?.success) throw Error("fixture browser authorization could not be provisioned");
  for (const trial of ["ideal-0","ideal-1","ideal-2","ideal-3","ideal-4","ideal-5","dephasing","missing","cancelled","unavailable"]) {
    const url = destination + "/?trial=" + trial;
    await send("Page.navigate", {url});
    const response = await until(() => responses.find(r => r.url === url && r.status === 200), trial + " network response");
    await until(() => value("location.href === " + JSON.stringify(url) + " && document.querySelector('#result')?.textContent === ''"),
                trial + " page readiness");
    const title = await value("document.querySelector('h1').textContent");
    await click("#run");
    const observed = await until(() => value("document.querySelector('#result')?.textContent"), trial + " button result");
    const {status, ...result} = JSON.parse(observed);
    evidence.trials[trial] = {page:title, status, result, security: response.securityDetails,
      browser_url: response.url, address:response.remoteIPAddress, port:response.remotePort};
  }
  socket.close();
} finally {
  await writeFile(join(root, "browser.json"), JSON.stringify(evidence));
  browser.kill("SIGTERM");
}
