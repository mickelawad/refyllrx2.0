import{getSupabase}from'./supabase-client.js';
const form=document.getElementById('f');
const statusEl=document.getElementById('st');
const p1=document.getElementById('p1');
const p2=document.getElementById('p2');
form.addEventListener('submit',async e=>{
  e.preventDefault();
  const button=form.querySelector('button[type="submit"]');
  button.disabled=true;button.textContent='Updating…';
  try{
    if(p1.value!==p2.value)throw Error('The passwords do not match.');
    if(p1.value.length<12)throw Error('Use a password of at least 12 characters.');
    const s=await getSupabase();
    const {data:{session}}=await s.auth.getSession();
    if(!session)throw Error('This reset link is invalid or expired. Request a new reset email.');
    const {error}=await s.auth.updateUser({password:p1.value});
    if(error)throw error;
    statusEl.textContent='Password updated successfully. You can now return to sign in.';
    statusEl.className='status show ok';
    form.reset();
  }catch(err){
    statusEl.textContent=err?.message||'Password could not be updated.';
    statusEl.className='status show err';
  }finally{
    button.disabled=false;button.textContent='Update password';
  }
});
