import { spawn } from "node:child_process";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
const [chrome, launch, target, operation = "configure", request = '{"name":"fixture-operator","protocol":1}', outcome = "applied"] = process.argv.slice(2);
const profile = await mkdtemp(join(tmpdir(), "cw-browser-"));
const browser = spawn(chrome, ["--headless", "--no-sandbox", "--disable-gpu",
  "--disable-background-networking", "--no-first-run", "--remote-debugging-port=0",
  "--user-data-dir=" + profile, "about:blank"], { stdio: "ignore" });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
try {
  let endpoint;
  for (let i = 0; i < 40; i++) {
    try { endpoint = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]; break; }
    catch { await wait(100); }
  }
  const [page] = await (await fetch("http://127.0.0.1:" + endpoint + "/json/list")).json();
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, {once: true});
    socket.addEventListener("error", reject, {once: true});
  });
  let id = 0;
  const callbacks = new Map();
  socket.addEventListener("message", event => {
    const data = JSON.parse(event.data);
    if (callbacks.has(data.id)) { callbacks.get(data.id)(data); callbacks.delete(data.id); }
  });
  const call = (method, params) => new Promise(resolve => {
    callbacks.set(++id, resolve);
    socket.send(JSON.stringify({id, method, params}));
  });
  async function value(expression) {
    const r = await call("Runtime.evaluate", {expression, returnByValue: true});
    return r.result?.result?.value;
  }
  async function decision(expected) {
    let last;
    for (let i = 0; i < 75; i++) {
      const result = await value("document.querySelector('#result')?.textContent");
      if (result) {
        last = JSON.parse(result);
        if (last.decision === expected) return last;
      }
      await wait(100);
    }
    throw Error("browser did not observe " + expected + "; last decision: " + (last?.decision ?? "none") + "; " + (last?.reason ?? ""));
  }
  async function click(id) {
    const selector = JSON.stringify("#" + id);
    const [x, y] = await value("(()=>{const e=document.querySelector(" + selector + ");e.scrollIntoView();const r=e.getBoundingClientRect();return [r.x+r.width/2,r.y+r.height/2]})()");
    for (const type of ["mousePressed", "mouseReleased"])
      await call("Input.dispatchMouseEvent", {type, x, y, button: "left", clickCount: 1});
  }
  await call("Page.navigate", {url: launch});
  const events = [await decision("session_ready")];
  if (operation === "install") {
    for (const [button, expected] of [["plan-button","verified_plan"],["approve-button","approved"],
        ["apply-button","installed"],["bootstrap-button","bootstrapped"]]) {
      await click(button);
      events.push({control: button, ...await decision(expected)});
    }
  } else {
    const fields = JSON.stringify({target, payload: request});
    await value("document.querySelector('select[name=action]').value=" + JSON.stringify(operation));
    await value("(()=>{const values=" + fields + ";for(const [id,value] of Object.entries(values))document.getElementById(id).value=value; return true})()");
    for (const [button, observed] of [["plan-button","planned"],["approve-button","approved"],["apply-button",outcome]]) {
      await click(button);
      events.push({control: button, ...await decision(observed)});
    }
  }
  console.log(JSON.stringify(events));
  socket.close();
} finally {
  browser.kill("SIGTERM");
  await Promise.race([new Promise(resolve => browser.once("exit", resolve)), wait(500)]);
  await rm(profile, {recursive:true,force:true,maxRetries:3});
}
