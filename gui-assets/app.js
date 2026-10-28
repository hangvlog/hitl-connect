'use strict';
const $=id=>document.getElementById(id);
const incoming=location.hash.slice(1);
if(incoming){sessionStorage.setItem('hitl-ui-session',incoming);history.replaceState(null,'','/');}
const token=sessionStorage.getItem('hitl-ui-session');
let role='host',state=null,busy=false,exited=false;
function displayText(text=''){return String(text).replace(/OpenSSH(?: Server)?/gi,'系统连接组件').replace(/SSH Agent/g,'密钥代理').replace(/SSH/g,'HITL Connect');}
function displayCode(code=''){return code.replace(/OPENSSH/g,'SYSTEM_CONNECTION').replace(/SSH/g,'HITL_CONNECT');}
function notice(text=''){$('notice').textContent=displayText(text);$('notice').hidden=!text;}
async function api(path,body){
 const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
 if(!response.ok){let text='操作未完成';try{const data=await response.json();text=data.error||text;}catch{if(response.status===401)text='面板访问凭证已失效，请重新双击程序打开';if(response.status===409)text='另一个检查仍在进行，请稍候';}throw Error(text);}
 return response.json();
}
function setRole(next){role=next;$('host-role').classList.toggle('active',role==='host');$('connect-role').classList.toggle('active',role==='connect');$('caller-fields').hidden=role!=='connect';$('login-fields').hidden=role!=='connect';$('target-wrap').hidden=role!=='host';$('provider-fields').hidden=role!=='host';$('listen-wrap').hidden=role!=='connect';$('start').textContent=role==='host'?'允许连接并生成连接码':'开始连接';}
function render(next){
 if(!state||next.running){setRole(next.role);if(next.address)$(next.role==='host'?'target':'listen').value=next.address;}state=next;const running=state.running,offline=!!state.managedUnavailable;
 $('running').textContent=running?'运行中':'未运行';$('running').classList.toggle('live',running);
 $('product-version').textContent='HITL Connect · '+(state.version||'development').split('+')[0];
 $('system-ssh-hint').hidden=state.sshEngine!=='openssh';
 $('embedded-ssh-hint').hidden=state.sshEngine==='openssh';
 for(const id of ['start','host-role','connect-role'])$(id).disabled=running||busy||offline;
 if(state.problem?.code==='RECONNECT_STOPPED')$('start').disabled=busy||offline;
 for(const id of ['code','target','listen'])$(id).disabled=running||busy||offline;
 for(const id of ['stop','diagnose'])$(id).disabled=!running||busy;
 $('trust').disabled=busy;$('quit').disabled=busy;
 $('diagnose').disabled=(!offline&&!running&&!state.configured)||busy;
 $('diagnose').textContent=offline?'检查后台服务':'检查连接';
 $('manual-ssh').disabled=running||busy;
 if(!$('local-user').value)$('local-user').value=state.authorizedUser||state.localUser||'';
 $('connect-role').disabled=running||busy||state.managed;
 $('local-user').disabled=running||busy||state.managed;
 $('privilege').disabled=running||busy||state.managed;if(state.privilege)$('privilege').value=state.privilege;
 $('start').textContent=offline?'后台服务不可用':state.configured&&role===state.role?'恢复连接':role==='host'?'允许连接并生成连接码':'开始连接';
 $('grant-status').hidden=!running||!state.authorizedUser;
 $('renew-code').disabled=busy; $('disable-code').disabled=busy||state.grantDisabled;
 $('grant-detail').textContent=state.grantDisabled?'连接码已手动停用。更换连接码后可重新授权。':'长期有效，已授权 '+(state.grantedDevices||0)+' 台设备。添加设备分享同一码；停用或更换会撤销全部旧授权。';
 $('invitation').hidden=!state.hasInvitation||!running;
 $('host-trust').hidden=!state.fingerprint;$('trust').hidden=!state.canTrust;$('trust-hint').textContent=state.role==='host'?'访问端会通过连接码自动核验此主机。':state.canTrust?'请与提供方核对主机指纹，确认是目标电脑后再保存信任。':'当前 HITL Connect 服务返回的指纹；信任验证结果见上方账号登录项。';$('fingerprint').textContent=state.fingerprint||'';
 $('identity').hidden=!state.loginIdentity||!state.steps.some(s=>s.id==='login'&&s.status==='passed');
 $('identity').textContent='远端身份：'+(state.loginIdentity||'');
 $('saved').textContent=state.savedCaller?'已有配对，可留空连接码直接连接。原身份会保留。':'首次连接请粘贴提供方的完整连接码。';
 const failed=state.steps.find(s=>s.status==='failed'),all=state.steps.every(s=>s.status==='passed');
 $('problem').hidden=!state.problem;
 $('problem-code').textContent=state.problem?displayCode(state.problem.code)+' · '+({provider:'提供端',relay:'中继',network:'网络',local:'本机'}[state.problem.side]||state.problem.side):'';
 $('problem-action').textContent=state.problem?displayText(state.problem.nextAction):'';
 if(offline&&state.service)$('problem-action').textContent+='（服务状态：'+state.service.state+(state.service.nativeCode===undefined?'':'；Windows 错误：'+state.service.nativeCode)+'）';
 $('headline').textContent=state.protocolVersion===3&&state.role==='host'?({online:'设备在线',suspect:'设备状态待确认',offline:'设备正在重连',draining:'等待现有会话结束'}[state.controlState]||'设备状态未知')+' · '+state.activeSessions+' 个会话 / '+state.idleChannels+' 个空闲通道':state.problem?.retryable?'正在自动恢复连接':failed?'卡在「'+displayText(failed.title)+'」':all?'HITL Connect 登录已验证':running?'正在确认连接状态':'从这里开始连接';
 $('steps').replaceChildren(...state.steps.map((s,i)=>{const row=document.createElement('div');row.className='step '+s.status;const mark=document.createElement('span');mark.className='mark';mark.textContent=({passed:'✓',failed:'!',working:'…',attention:'?'})[s.status]||String(i+1);const text=document.createElement('div'),title=document.createElement('b'),detail=document.createElement('p');title.textContent=displayText(s.title);detail.textContent=displayText(s.detail);text.append(title,detail);row.append(mark,text);return row;}));
 $('events').replaceChildren(...(state.events.length?state.events:['等待启动。']).map(text=>{const li=document.createElement('li');li.textContent=displayText(text);return li;}));
 $('checked').textContent=state.checkedAt?'最近检查：'+new Date(state.checkedAt).toLocaleTimeString():'';
}
async function refresh(){if(exited)return;try{render(await api('state'));}catch(e){notice(e.message);}}
async function action(name,body){busy=true;notice();if(state)render(state);try{const result=await api(name,body);if(result.ok===false)throw Error((result.code||'')+' '+(result.message||'操作未完成'));if(name!=='quit')await refresh();return result;}catch(e){notice(e.message);return null;}finally{busy=false;if(state)render(state);}}
async function copy(text){if(!text)throw Error('还没有可复制的内容');await navigator.clipboard.writeText(text);}
$('host-role').onclick=()=>setRole('host');$('connect-role').onclick=()=>setRole('connect');
$('start').onclick=async()=>{const result=await action(role==='host'?'allow':'start',{role,relay:role==='host'?$('relay').value.trim():'',privilege:role==='host'?$('privilege').value:'',user:role==='host'?$('local-user').value.trim():$('user').value.trim(),connectionKey:$('code').value.trim(),target:$('target').value.trim(),listen:$('listen').value.trim(),manualSSH:$('manual-ssh').checked,keyPath:$('keypath').value.trim()});if(result)$('code').value='';};
$('disable-code').onclick=()=>action('disable-code',{});
$('renew-code').onclick=()=>action('renew',{});
$('stop').onclick=()=>action('stop',{});
$('diagnose').onclick=()=>action('diagnose',state?.managedUnavailable?{}:{user:$('user').value.trim(),keyPath:$('keypath').value.trim()});
$('trust').onclick=()=>action('trust',{fingerprint:state?.fingerprint||''});
$('copy-key').onclick=async()=>{try{const data=await api('invitation',{});await copy(data.connectionKey);$('key-status').textContent='已复制，请仅分享给获准访问的人。';}catch(e){notice(e.message);}};
$('copy-report').onclick=async()=>{try{if(!state)return;await copy(JSON.stringify({product:'HITL Connect',version:state.version,role:state.role,running:state.running,checkedAt:state.checkedAt,problem:state.problem?{...state.problem,code:displayCode(state.problem.code),message:displayText(state.problem.message),nextAction:displayText(state.problem.nextAction)}:null,service:state.service,loginExitCode:state.nativeSshExitCode,steps:state.steps.map(s=>({...s,title:displayText(s.title),detail:displayText(s.detail)})),events:state.events.map(displayText)},null,2));notice('脱敏诊断已复制。');}catch(e){notice(e.message);}};
$('quit').onclick=async()=>{const result=await action('quit',{});if(result){exited=true;notice('程序已退出，可以关闭此页面。');for(const button of document.querySelectorAll('button'))button.disabled=true;}};
if(!token){notice('请双击 HITL Connect 程序打开管理面板。');for(const button of document.querySelectorAll('button'))button.disabled=true;}else{refresh();setInterval(()=>{if(!document.hidden)refresh();},3000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});}

async function renderHTTP(){
 try{const data=await api('http-services',{});$('http-list').replaceChildren();
 if(data.reconnectStopped){const resume=document.createElement('button');resume.textContent='自动重连已停止 · 手动重试';resume.onclick=async()=>{await action('http-resume',{});await renderHTTP()};$('http-list').append(resume)}
 for(const service of data.items){const row=document.createElement('div'),label=document.createElement('p'),url=document.createElement('code'),copy=document.createElement('button'),disable=document.createElement('button');
 label.textContent=service.name+' → '+service.target+' · '+(!service.enabled?'已停用':data.connected?'已连接，等待调用':data.reconnectStopped?'自动重连已停止':'等待连接');url.textContent=service.url;copy.textContent='复制调用配置';disable.textContent='停用';disable.disabled=!service.enabled;
 copy.onclick=async()=>{try{const result=await api('http-credentials',{serviceName:service.name});await navigator.clipboard.writeText(JSON.stringify(result,null,2));notice('调用配置已复制，请私密保存 Token');}catch(e){notice(e.message)}};
 disable.onclick=async()=>{try{await api('http-disable',{serviceName:service.name});await renderHTTP();}catch(e){notice(e.message)}};
 row.append(label,url,copy,disable);$('http-list').append(row);}
 }catch(e){notice(e.message)}
}
$('http-refresh').onclick=renderHTTP;
$('http-publish').onclick=async()=>{try{await api('http-publish',{httpPort:Number($('http-port').value),serviceName:$('http-name').value.trim()});await renderHTTP();notice('发布配置已保存；客户端连接服务器后生效，请通过接口验证可用性。');}catch(e){notice(e.message)}};
