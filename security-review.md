# RefyllRx Security Review — 2026-08-16

## Remediated in this pass

- Restored strict database ownership checks for refill and delivery requests.
- Made assessment submissions go through a server-side RPC so direct inserts cannot bypass assessment consent records.
- Made the original assessment intake immutable after submission.
- Made secure messages append-only and server-controlled their timestamps/read state on insert.
- Blocked ordinary patient sessions from changing professional licence/credential fields.
- Made refill/delivery patient-submitted identity fields immutable after creation.
- Tightened unnecessary authenticated database privileges on sensitive tables.
- Froze browser writes to the unused legacy `assessments` clinical-decision table until stronger clinical authorization is implemented.
- Fixed a JavaScript module parse defect in `app.js`.
- Aligned professional assessment status buttons with the database status constraint.
- Removed inline JavaScript from auth callback/password-reset pages.
- Added a strict Netlify Content Security Policy and standard browser security headers.
- Added `noopener noreferrer` to links that open a new tab.

## Residual findings requiring an operator/security decision

### Clinical/admin role separation
`super_user` is currently treated as staff and also as a prescriber by the backend role helpers. The legacy clinical-decision table has now been frozen from browser writes, so this is not an active browser write path, but the role model must be separated before clinical decision functionality is enabled again.

### Service-specific clinical authorization
The older `assessments` table has been made read-only for browser-authenticated sessions. Before enabling writes again, implement service/scope-specific clinical authorization rather than treating every professional role as authorized for every clinical decision.


### Professional MFA enforcement
The current professional portal does not require an `aal2` Supabase session. Before production PHI access, add MFA enrollment/challenge support and enforce `auth.jwt()->>'aal' = 'aal2'` for professional/staff data access at the database level. Supabase documents this as an RLS enforcement pattern.

### OAuth onboarding completeness
A new Google-authenticated account can obtain an authenticated session without completing the full demographic/registration-consent form. Clinical submission is forced through the assessment RPC, but production should add a server-enforced onboarding-complete condition before accepting clinical assessments.

### Browser-held sessions
The custom frontend client stores Supabase access/refresh tokens in `localStorage`. The new CSP materially reduces XSS exposure, but a server-managed HttpOnly-cookie architecture would further reduce token theft risk for a healthcare portal.

### Uploaded document malware screening
Insurance files are private, owner-scoped, size-limited and MIME-restricted. The system does not currently perform content inspection or malware scanning before staff download/open a patient-supplied document.

### Supabase password protection setting
Supabase Auth currently reports leaked-password protection as disabled. Enable it in the Supabase dashboard before production use.


## Supabase advisor notes

- The database advisor warns that `public.submit_assessment_request(...)` is an authenticated `SECURITY DEFINER` RPC. This is intentional in the current design because direct table inserts are revoked and the RPC explicitly binds `patient_id` to `auth.uid()`, validates the service and input length, and writes the assessment consent records atomically. For a cleaner long-term architecture, move the privileged implementation out of the exposed API schema or to a server/Edge Function.
- Leaked-password protection remains disabled and must be enabled in the Supabase Auth dashboard.

Advisor references:
- https://supabase.com/docs/guides/database/database-linter?lint=0029_authenticated_security_definer_function_executable
- https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection
- https://supabase.com/docs/guides/auth/auth-mfa
