import {connect} from 'node:tls';
import {request} from 'node:https';
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
          .slice(0,30).map(e=>(e.innerText.trim()||e.getAttribute('aria-label')||e.getAttribute('title')||e.getAttribute('href')||'').slice(0,100)).filter(Boolean),
        inputs:[...document.querySelectorAll('input')].filter(e=>e.getClientRects().length)
          .map(e=>({name:e.name,placeholder:e.placeholder,type:e.type}))
      })).catch(()=>({})));
    }
    receipt.steps.push({label,pathname:new URL(page.url()).pathname,frames});
  };
  for(let turn=0;turn<35;turn++){
    await page.waitForTimeout(650);
    await snapshot('supported UI step '+turn);
    if(await click(/^(Integrations|API Keys)$/i)) break;
    const integration=page.locator('a[href="/network/default/integrations"]').first();
    if(!page.url().includes('/integrations') && await integration.isVisible()){await integration.click();break;}
    const settings=page.locator('a[href*="/settings"],[aria-label="Settings" i],[title="Settings" i]').first();
    if(page.url().endsWith('/dashboard') && await settings.isVisible()){await settings.click();continue;}
    if(await click(/^(?:Continue Anyway|Go To Dashboard)$/i)) continue;
    if(await click(/^(Proceed Without a UI Account|Settings|Control Plane)$/i)) continue;
    if(!page.url().includes("/network") && await click(/^(Network|UniFi Network)$/i)) continue;
    if(await click(/^(Integrations|API Keys)$/i)) break;
    if(await click(/^(Advanced Setup|Set Up Offline|Offline Setup|Local Setup|Create Local Account|Use Local Account|Continue Without (a )?UI Account)$/i)) continue;
    await fill('input[name*="name" i]:not([type=password]),input[placeholder*="server name" i]','Commonwealth Cloud Fixture');
    const local=await page.locator('input[type=password]').count();
    if(local){
      const text=await page.locator('body').innerText();
      if(!/local|offline|sign in to your console/i.test(text) && !await page.locator('input[name*="local" i]').count()) throw Error('cloud sign-in only; local setup not exposed');
      const terms=page.locator('input[name="tosAndEula"]');
      if(page.url().includes('/setup/') && await page.locator('input[name="localPassword"]').count() && await terms.count()){
        await terms.check({timeout:3000});
        receipt.local_terms_accepted=true;
      }
      for(const item of await page.locator('input[type=password]').all())if(await item.isVisible())await item.fill(password);
      await fill('input[autocomplete=username],input[name*="username" i],input[placeholder*="username" i]','cw-fixture-admin');
    }
    if(await click(/^(Get Started|Start Setup|Continue|Next|Finish Setup|Set Up|Create Account|Create|Sign In|Finish|Confirm)$/i))continue;
  }
  await page.waitForTimeout(2000);
  await snapshot('before fixture key creation');
  if(!await click(/^(Create New API Key|Create API Key|Generate API Key|New API Key)$/i))throw Error('supported Integrations API key control not reached');
  await page.waitForTimeout(500);
  await snapshot('key form');
  await page.locator('input[name=keyName]').fill('Commonwealth disposable fixture');
  if(!await click(/^Create$/i))throw Error('fixture key submit unavailable');
  await page.waitForTimeout(750);
  await page.getByRole('heading',{name:'API Key Created'}).waitFor({timeout:8000});
  let key=await page.evaluate(()=>{
    const fields=[...document.querySelectorAll('input,textarea')].filter(e=>e.getClientRects().length);
    return fields.map(e=>e.value).find(v=>/^[A-Za-z0-9_+\-=/]{24,256}$/.test(v))||null;
  });
  if(!key){
    await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:base});
    const copy=page.locator('button[title*="copy" i],button[aria-label*="copy" i]').or(page.getByRole('button',{name:/^copy(?: api key)?$/i})).first();
    if(await copy.isVisible()){
      await copy.click();
      key=await page.evaluate(()=>navigator.clipboard.readText());
    }
  }
  if(!key||key.length<24||key.length>256)throw Error('one-time key unavailable in supported UI');
  receipt.fixture_key_provisioned=true;
  const host='127.0.0.1',port=11443;
  const fingerprint=socket=>createHash('sha256').update(socket.getPeerCertificate().raw).digest('hex');
  // Bootstrap trust from the isolated loopback controller, then pin before sending any HTTP bytes.
  const pin=await new Promise((resolve,reject)=>{
    const socket=connect({host,port,rejectUnauthorized:false},()=>{
      try{resolve(fingerprint(socket));}catch(error){reject(error);}finally{socket.destroy();}
    });
    socket.on('error',reject);
    socket.setTimeout(5000,()=>socket.destroy(Error('fixture TLS timeout')));
  });
  receipt.transport={trust:'isolated loopback certificate pin',certificate_sha256:pin,cookies:false};
  const probe=(route,credential)=>new Promise((resolve,reject)=>{
    const headers={Accept:'application/json'};
    if(credential)headers['X-API-Key']=credential;
    const req=request({host,port,path:route,headers,agent:false,rejectUnauthorized:false},res=>{
      const chunks=[];
      let size=0;
      res.on('data',chunk=>{
        size+=chunk.length;
        if(size>262144){req.destroy(Error('fixture response exceeded byte limit'));return;}
        chunks.push(chunk);
      });
      res.on('error',reject);
      res.on('end',()=>{
        const bytes=Buffer.concat(chunks);
        let body;
        try{body=JSON.parse(bytes.toString('utf8'));}catch{}
        const paginated=Boolean(Array.isArray(body?.data)&&body.count===body.data.length&&
          ['count','totalCount','offset','limit'].every(k=>Number.isInteger(body[k])));
        resolve({status:res.statusCode,media:res.headers['content-type']||'',paginated,
          count:paginated?body.totalCount:null,body_sha256:createHash('sha256').update(bytes).digest('hex')});
      });
    });
    req.on('error',reject);
    req.setTimeout(6000,()=>req.destroy(Error('fixture HTTP timeout')));
    req.on('socket',socket=>socket.once('secureConnect',()=>{
      try{
        if(fingerprint(socket)!==pin)throw Error('controller certificate pin mismatch');
        req.end();
      }catch(error){req.destroy(error);}
    }));
  });
  receipt.probes=[];
  for(const route of ['/proxy/network/integration/v1/sites','/integration/v1/sites']){
    const missing=await probe(route);
    const wrong=await probe(route,'invalid-fixture-key');
    const valid=await probe(route,key);
    receipt.probes.push({route,valid,missing,wrong});
    if(valid.status===200&&valid.media.startsWith('application/json')&&valid.paginated&&
      [missing,wrong].every(result=>[401,403].includes(result.status)&&!result.paginated)){
      receipt.authenticated_json=true;
      receipt.documented_route=route;
      break;
    }
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
