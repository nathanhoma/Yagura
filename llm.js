'use strict';
const {isLocalIp}=require('./workflow');
function isPrivateLlmUrl(value) {
  try {
    const u=new URL(value),h=u.hostname.toLowerCase();
    return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password&&!u.search&&!u.hash&&(h==='localhost'||h.endsWith('.localhost')||h==='[::1]'||isLocalIp(h));
  }catch{return false;}
}
class LlmError extends Error {
  constructor(code,message){super(message);this.name='LlmError';this.code=code;}
}
function connectionError(error) {
  if(error instanceof LlmError)return error;
  if(error.name==='TimeoutError'||error.name==='AbortError')return new LlmError('timeout','The local model request timed out.');
  const code=error.cause?.code;
  if(code==='ECONNREFUSED')return new LlmError('unreachable','The local model connection was refused.');
  if(code==='ECONNRESET')return new LlmError('unreachable','The local model connection was reset.');
  return new LlmError('unreachable','The local model endpoint could not be reached.');
}
function createLlmService({baseUrl='',model='',apiKey='',request=fetch,timeoutMs=30000}={}) {
  const base=baseUrl.replace(/\/$/,'');let resolvedModel='';
  const timeout=Math.max(100,Math.min(60000,Number(timeoutMs)||30000));
  function configuration(){return {configured:!!base,allowed:!!base&&isPrivateLlmUrl(base),model:model||resolvedModel||null,autoSelect:!model};}
  function assertConfiguration(){
    if(!base)throw new LlmError('not-configured','Configure LLM_BASE_URL to enable the local model.');
    if(!isPrivateLlmUrl(base))throw new LlmError('blocked','LLM_BASE_URL must use localhost or a private IP without credentials, query strings, or fragments.');
  }
  async function call(route,body) {
    assertConfiguration();
    try {
      const response=await request(`${base}${route}`,{method:body?'POST':'GET',redirect:'error',signal:AbortSignal.timeout(timeout),headers:{'Content-Type':'application/json',...(apiKey?{Authorization:`Bearer ${apiKey}`}:{})},...(body?{body:JSON.stringify(body)}:{})});
      if(!response.ok)throw new LlmError(response.status===401||response.status===403?'authentication':'provider-error',`The local model returned HTTP ${response.status}.`);
      try{return await response.json();}catch{throw new LlmError('invalid-response','The local model returned an unreadable response.');}
    }catch(e){throw connectionError(e);}
  }
  async function models(){
    const data=await call('/models');
    if(!Array.isArray(data?.data))throw new LlmError('invalid-response','The model list is not in OpenAI-compatible format.');
    return [...new Set(data.data.filter(m=>m&&typeof m.id==='string'&&m.id.trim()).map(m=>m.id))];
  }
  async function selectModel(list,requested='') {
    if(requested){const ids=list||await models();if(!ids.includes(requested))throw new LlmError('model-unavailable','The selected model is not in the endpoint model list.');return requested;}
    if(model)return model;
    if(resolvedModel)return resolvedModel;
    const ids=list||await models();
    if(ids.length!==1)throw new LlmError('model-required',ids.length?'Several models are available. Set LLM_MODEL explicitly.':'No model is available. Start a model and set LLM_MODEL.');
    resolvedModel=ids[0];return resolvedModel;
  }
  async function health() {
    let ids=[];
    try {
      ids=await models();const selected=await selectModel(ids);
      if(!ids.includes(selected))throw new LlmError('model-unavailable','The configured LLM_MODEL is not in the endpoint model list.');
      return {...configuration(),status:'ready',model:selected,models:ids};
    }catch(e){return {...configuration(),status:e.code||'unreachable',message:e.message,models:ids};}
  }
  async function complete(messages,{maxTokens=1600,model:requestedModel=''}={}) {
    assertConfiguration();const selected=await selectModel(null,requestedModel);
    const data=await call('/chat/completions',{model:selected,temperature:0.1,max_tokens:maxTokens,response_format:{type:'json_object'},messages});
    const raw=data?.choices?.[0]?.message?.content;
    if(typeof raw!=='string'||!raw.trim())throw new LlmError('invalid-response','The local model returned no JSON content.');
    if(data.choices[0].finish_reason==='length')throw new LlmError('invalid-response','The local model response was truncated.');
    const content=raw.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/i,'$1');
    let parsed;try{parsed=JSON.parse(content);}catch{throw new LlmError('invalid-response','The local model content was not valid JSON.');}
    if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new LlmError('invalid-response','The local model content must be a JSON object.');
    return {data:parsed,model:selected};
  }
  return {configuration,health,complete};
}
module.exports={createLlmService,isPrivateLlmUrl,LlmError};
