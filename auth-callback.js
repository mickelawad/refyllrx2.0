import{getSupabase}from'./supabase-client.js';
const statusEl=document.getElementById('st');
try{
  statusEl.textContent='Completing secure sign-in…';
  const s=await getSupabase();
  const {data:{session},error}=await s.auth.getSession();
  if(error)throw error;
  if(!session){
    statusEl.className='status show err';
    statusEl.textContent='Google sign-in returned, but no secure session was received. Please return to RefyllRx and try again.';
  }else{
    const {data:{user},error:userError}=await s.auth.getUser();
    if(userError)throw userError;
    statusEl.className='status show ok';
    statusEl.textContent=`Signed in${user?.email?' as '+user.email:''}. Opening your portal…`;
    setTimeout(()=>location.replace('index.html'),500);
  }
}catch(err){
  statusEl.className='status show err';
  statusEl.textContent=err?.message||'Could not complete sign-in.';
}
