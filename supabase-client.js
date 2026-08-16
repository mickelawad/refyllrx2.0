
import {SUPABASE_URL,SUPABASE_PUBLISHABLE_KEY} from './config.js';

const STORAGE_KEY = 'refyllrx.supabase.session.v1';
const listeners = new Set();
let refreshPromise = null;

function authHeaders(token, extra={}){
  return {
    'apikey': SUPABASE_PUBLISHABLE_KEY,
    ...(token ? {'Authorization': `Bearer ${token}`} : {}),
    ...extra
  };
}

function makeError(payload, fallback='Request failed'){
  const message = payload?.msg || payload?.message || payload?.error_description || payload?.error || fallback;
  const err = new Error(message);
  err.status = payload?.status || payload?.code || 0;
  return err;
}

async function jsonFetch(url, options={}){
  let res;
  try{
    res = await fetch(url, options);
  }catch(e){
    throw new Error('Network request failed. Please check your connection and try again.');
  }
  let data = null;
  const text = await res.text();
  if(text){
    try{ data = JSON.parse(text); }catch{ data = text; }
  }
  if(!res.ok) throw makeError(data, `Request failed (${res.status})`);
  return data;
}

function saveSession(session){
  if(session) localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  else localStorage.removeItem(STORAGE_KEY);
}
function readSession(){
  try{
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  }catch{
    return null;
  }
}
function normalizeSession(data){
  if(!data?.access_token) return null;
  const expiresAt = data.expires_at || (Math.floor(Date.now()/1000) + Number(data.expires_in || 3600));
  return {
    access_token:data.access_token,
    refresh_token:data.refresh_token,
    token_type:data.token_type || 'bearer',
    expires_in:Number(data.expires_in || 3600),
    expires_at:expiresAt,
    user:data.user || null
  };
}
function emit(event, session){
  for(const cb of listeners){
    try{ cb(event, session); }catch(e){ console.error(e); }
  }
}

function captureSessionFromUrl(){
  const hash = location.hash?.startsWith('#') ? location.hash.slice(1) : '';
  if(!hash) return;
  const p = new URLSearchParams(hash);
  const access_token = p.get('access_token');
  const refresh_token = p.get('refresh_token');
  if(!access_token || !refresh_token) return;
  const expires_in = Number(p.get('expires_in') || 3600);
  const session = normalizeSession({access_token,refresh_token,expires_in,token_type:p.get('token_type') || 'bearer'});
  saveSession(session);
  history.replaceState(null, document.title, location.pathname + location.search);
}

captureSessionFromUrl();

async function refreshSession(){
  if(refreshPromise) return refreshPromise;
  refreshPromise = (async()=>{
    const current = readSession();
    if(!current?.refresh_token) return null;
    try{
      const data = await jsonFetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`,{
        method:'POST',
        headers:authHeaders(null,{'Content-Type':'application/json'}),
        body:JSON.stringify({refresh_token:current.refresh_token})
      });
      const session = normalizeSession(data);
      saveSession(session);
      emit('TOKEN_REFRESHED',session);
      return session;
    }catch(e){
      saveSession(null);
      emit('SIGNED_OUT',null);
      return null;
    }finally{
      refreshPromise = null;
    }
  })();
  return refreshPromise;
}

async function validSession(){
  let s = readSession();
  if(!s) return null;
  if(!s.expires_at || s.expires_at <= Math.floor(Date.now()/1000)+45){
    s = await refreshSession();
  }
  return s;
}

async function authedFetch(path, options={}, retry=true){
  let session = await validSession();
  if(!session?.access_token) throw new Error('Your session has expired. Please sign in again.');
  try{
    return await jsonFetch(`${SUPABASE_URL}${path}`,{
      ...options,
      headers:authHeaders(session.access_token, options.headers || {})
    });
  }catch(e){
    if(retry && (e.status===401 || String(e.message).toLowerCase().includes('jwt'))){
      session = await refreshSession();
      if(session?.access_token) return authedFetch(path,options,false);
    }
    throw e;
  }
}

class QueryBuilder{
  constructor(table){
    this.table=table; this.method='GET'; this.body=null; this.params=new URLSearchParams();
    this.headers={}; this.singleMode=false;
  }
  select(cols='*'){ this.params.set('select',cols); return this; }
  eq(col,val){ this.params.append(col,`eq.${val}`); return this; }
  order(col,{ascending=true}={}){ this.params.set('order',`${col}.${ascending?'asc':'desc'}`); return this; }
  limit(n){ this.params.set('limit',String(n)); return this; }
  maybeSingle(){ this.singleMode=true; return this; }
  insert(data){ this.method='POST'; this.body=data; this.headers['Prefer']='return=representation'; return this; }
  update(data){ this.method='PATCH'; this.body=data; this.headers['Prefer']='return=representation'; return this; }
  async execute(){
    try{
      const qs=this.params.toString();
      const data=await authedFetch(`/rest/v1/${encodeURIComponent(this.table)}${qs?'?'+qs:''}`,{
        method:this.method,
        headers:{'Content-Type':'application/json',...this.headers},
        ...(this.body!==null?{body:JSON.stringify(this.body)}:{})
      });
      if(this.singleMode){
        const value=Array.isArray(data)?(data[0]??null):(data??null);
        return {data:value,error:null};
      }
      return {data:data??[],error:null};
    }catch(error){ return {data:null,error}; }
  }
  then(resolve,reject){ return this.execute().then(resolve,reject); }
}

const auth = {
  async signInWithPassword({email,password}){
    try{
      const data=await jsonFetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`,{
        method:'POST',
        headers:authHeaders(null,{'Content-Type':'application/json'}),
        body:JSON.stringify({email,password})
      });
      const session=normalizeSession(data);
      if(!session) throw new Error('Sign-in completed without a valid session.');
      saveSession(session); emit('SIGNED_IN',session);
      return {data:{user:data.user,session},error:null};
    }catch(error){ return {data:{user:null,session:null},error}; }
  },
  async signUp({email,password,options={}}){
    try{
      const redirect=options.emailRedirectTo ? `?redirect_to=${encodeURIComponent(options.emailRedirectTo)}` : '';
      const data=await jsonFetch(`${SUPABASE_URL}/auth/v1/signup${redirect}`,{
        method:'POST',
        headers:authHeaders(null,{'Content-Type':'application/json'}),
        body:JSON.stringify({email,password,data:options.data||{}})
      });
      const session=normalizeSession(data);
      if(session){ saveSession(session); emit('SIGNED_IN',session); }
      return {data:{user:data?.user||data,session},error:null};
    }catch(error){ return {data:{user:null,session:null},error}; }
  },
  async getSession(){
    const session=await validSession();
    return {data:{session},error:null};
  },
  async getUser(){
    try{
      const session=await validSession();
      if(!session?.access_token) return {data:{user:null},error:new Error('No authenticated user.')};
      const user=await authedFetch('/auth/v1/user',{method:'GET'});
      if(user){
        const current=readSession();
        if(current){ current.user=user; saveSession(current); }
      }
      return {data:{user},error:null};
    }catch(error){ return {data:{user:null},error}; }
  },
  async signInWithOAuth({provider,options={}}){
    try{
      const redirectTo=options.redirectTo||`${location.origin}/`;
      const url=`${SUPABASE_URL}/auth/v1/authorize?provider=${encodeURIComponent(provider)}&redirect_to=${encodeURIComponent(redirectTo)}`;
      location.assign(url);
      return {data:{provider,url},error:null};
    }catch(error){ return {data:null,error}; }
  },
  async signOut(){
    const session=readSession();
    try{
      if(session?.access_token){
        await jsonFetch(`${SUPABASE_URL}/auth/v1/logout`,{
          method:'POST',headers:authHeaders(session.access_token,{'Content-Type':'application/json'})
        });
      }
    }catch{}
    saveSession(null); emit('SIGNED_OUT',null);
    return {error:null};
  },
  async resetPasswordForEmail(email,{redirectTo}={}){
    try{
      const q=redirectTo?`?redirect_to=${encodeURIComponent(redirectTo)}`:'';
      await jsonFetch(`${SUPABASE_URL}/auth/v1/recover${q}`,{
        method:'POST',headers:authHeaders(null,{'Content-Type':'application/json'}),body:JSON.stringify({email})
      });
      return {data:{},error:null};
    }catch(error){ return {data:null,error}; }
  },
  async updateUser(attrs){
    try{
      const data=await authedFetch('/auth/v1/user',{
        method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(attrs)
      });
      return {data:{user:data},error:null};
    }catch(error){ return {data:null,error}; }
  },
  onAuthStateChange(callback){
    listeners.add(callback);
    return {data:{subscription:{unsubscribe:()=>listeners.delete(callback)}}};
  }
};

function storagePath(path=''){return String(path).split('/').filter(Boolean).map(encodeURIComponent).join('/');}
class StorageBucket{constructor(bucket){this.bucket=bucket;}async upload(path,file,{contentType,upsert=false}={}){try{const headers={'Content-Type':contentType||file?.type||'application/octet-stream','x-upsert':upsert?'true':'false'};const data=await authedFetch(`/storage/v1/object/${encodeURIComponent(this.bucket)}/${storagePath(path)}`,{method:'POST',headers,body:file});return {data,error:null};}catch(error){return {data:null,error};}}}

const client = {
  auth,
  storage:{from(bucket){return new StorageBucket(bucket);}},
  from(table){ return new QueryBuilder(table); },
  async rpc(name,args={}){
    try{
      const data=await authedFetch(`/rest/v1/rpc/${encodeURIComponent(name)}`,{
        method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(args)
      });
      return {data,error:null};
    }catch(error){ return {data:null,error}; }
  }
};

export async function getSupabase(){ return client; }
