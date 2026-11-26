import {createRequire} from 'node:module';
import {randomBytes, createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
const [modulePath,out,sha] = process.argv.slice(2);
const {chromium} = createRequire(modulePath + '/package.json')('playwright');
const receipt = {revision:sha,scope:'disposable local UniFi UI',authenticated_json:false,steps:[]};
const base='https://127.0.0.1:11443';
let browser;
try {
  browser=await chromium.launch({args:['--no-sandbox','--disable-background-networking','--no-proxy-server']});
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  const page=await context.newPage();
  await page.goto(base,{waitUntil:'domcontentloaded',timeout:20000});
  const password='Aa1!'+randomBytes(18).toString('hex');
  const click=async name=>{
    const candidates=page.getByRole('button',{name}).or(page.getByRole('link',{name}));
    for(const item of await candidates.all()){
      if(await item.isVisible() && await item.isEnabled()){await item.click({timeout:3000});return true;}
    }
    return false;
  };
  const fill=async (selector,value)=>{
    for(const input of await page.locator(selector).all()){
      if(await input.isVisible()&&await input.isEditable()&&!(await input.inputValue())){
        await input.fill(value);return true;
      }
    }
    return false;
  };
  const snapshot=async label=>{
    const frames=[];
    for(const frame of page.frames()){
      frames.push(await frame.evaluate(()=>({
        title:document.title,
        headings:[...document.querySelectorAll('h1,h2,h3')].slice(0,16).map(e=>e.innerText.slice(0,100)),
        buttons:[...document.querySelectorAll('button,a')].filter(e=>e.getClientRects().length)
          .slice(0,30).map(e=>e.innerText.trim().slice(0,100)).filter(Boolean),
        inputs:[...document.querySelectorAll('input')].filter(e=>e.getClientRects().length)
          .map(e=>({name:e.name,placeholder:e.placeholder,type:e.type}))
      })).catch(()=>({})));
    }
    receipt.steps.push({label,pathname:new URL(page.url()).pathname,frames});
  };
  for(let turn=0;turn<16;turn++){
    await page.waitForTimeout(650);
    await snapshot('supported UI step '+turn);
    if(await click(/^(Integrations|API Keys)$/i)) break;
    if(await click(/^(Continue Anyway|Proceed Without a UI Account|Settings|Control Plane)$/i)) continue;
    if(!page.url().includes("/network") && await click(/^(Network|UniFi Network)$/i)) continue;
    if(await click(/^(Integrations|API Keys)$/i)) break;
    if(await click(/^(Advanced Setup|Set Up Offline|Offline Setup|Local Setup|Create Local Account|Use Local Account|Continue Without (a )?UI Account)$/i)) continue;
    await fill('input[name*="name" i]:not([type=password]),input[placeholder*="server name" i]','Commonwealth Cloud Fixture');
    const local=await page.locator('input[type=password]').count();
    if(local){
      const text=await page.locator('body').innerText();
      if(!/local|offline|sign in to your console/i.test(text) && !await page.locator('input[name*="local" i]').count()) throw Error('cloud sign-in only; local setup not exposed');
      for(const item of await page.locator('input[type=password]').all())if(await item.isVisible())await item.fill(password);
      await fill('input[autocomplete=username],input[name*="username" i],input[placeholder*="username" i]','cw-fixture-admin');
    }
    if(await click(/^(Get Started|Start Setup|Continue|Next|Finish Setup|Set Up|Create Account|Create|Sign In|Finish|Confirm)$/i))continue;
  }
  await snapshot('before fixture key creation');
  if(!await click(/^(Create API Key|Generate API Key|New API Key)$/i))throw Error('supported Integrations API key control not reached');
  await page.waitForTimeout(500);
  await fill('input[type=text],input:not([type])','Commonwealth disposable fixture');
  await click(/^(Create|Generate|Create API Key|Generate API Key)$/i);
  await page.waitForTimeout(750);
  // Look only in form controls explicitly marked as API key or in the new-key dialog.
  const key=await page.evaluate(()=>{
    const fields=[...document.querySelectorAll('input,textarea')];
    const candidates=fields.filter(e=>e.readOnly||/api.?key/i.test(e.name+' '+e.placeholder))
      .map(e=>e.value);
    const dialog=document.querySelector('[role=dialog]');
    if(dialog)for(const e of dialog.querySelectorAll('code,pre'))candidates.push(e.textContent.trim());
    return candidates.find(v=>/^[A-Za-z0-9_+\-=/]{24,256}$/.test(v))||null;
  });
  if(!key)throw Error('no API key obtained from supported UI controls');
  receipt.fixture_key_provisioned=true;
  receipt.probes=[];
  for(const route of ['/proxy/network/integration/v1/sites','/integration/v1/sites']){
    const result=await context.request.get(base+route,{headers:{Accept:'application/json','X-API-Key':key},maxRedirects:0,timeout:6000});
    const bytes=await result.body();
    let body;
    try {body=JSON.parse(bytes.toString('utf8'));}catch{}
    const signedShape=Boolean(body&&Array.isArray(body.data)&&Number.isInteger(body.totalCount));
    const media=result.headers()['content-type']||'';
    const negative=await context.request.get(base+route,{headers:{Accept:'application/json','X-API-Key':'invalid-fixture-key'},maxRedirects:0,timeout:6000});
    const negativeJson=await negative.json().catch(()=>null);
    const accepted=result.status()===200 && media.startsWith('application/json')&&signedShape &&
      !(negative.status()===200&&Array.isArray(negativeJson?.data));
    receipt.probes.push({route,status:result.status(),media,paginated_sites:signedShape,
      invalid_key_status:negative.status(),body_sha256:createHash('sha256').update(bytes).digest('hex')});
    if(accepted){receipt.authenticated_json=true;receipt.documented_route=route;break;}
  }
  if(!receipt.authenticated_json)throw Error('fixture key did not produce authenticated sites JSON');
} catch(error) {
  receipt.blocker=String(error.message).split('\n')[0].slice(0,250);
  process.exitCode=2;
} finally {
  receipt.verdict=receipt.authenticated_json?'PASS':'UNVERIFIED';
  await writeFile(out,JSON.stringify(receipt,null,2));
  console.log(JSON.stringify(receipt));
  if(browser)await browser.close();
}
