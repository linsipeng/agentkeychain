import {SendCode} from './SendCode';
import { createContext, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link, NavLink, Navigate, Outlet, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, passkey, PasskeyIncompleteError, stepUp, supported } from './api';
import { en, zh, type Key } from './i18n';
const Risk = createContext<{
    failed: boolean;
    setFailed: (v: boolean) => void;
}>({ failed: false, setFailed: () => { } });
const Copy = createContext<(k: Key) => string>(k => en[k]);
const Join = createContext<{
    invite: string;
    verificationId: string;
    setInvite: (s: string) => void;
    setVerification: (s: string) => void;
}>({ invite: '', verificationId: '', setInvite: () => { }, setVerification: () => { } });
const label = (s: unknown, t: (k: Key) => string, fallback: Key = 'details') => t(typeof s === 'string' && s in en ? s as Key : fallback);
const date = (n?: number) => n ? new Date(n * 1000).toLocaleString() : '—';
interface Item {
    id: string;
    state?: string;
    action?: string;
    deviceId?: string;
    itemRef?: string;
    createdAt?: number;
    expiresAt?: number;
    canAllow?: boolean;
    allowRef?: string | null;
    denyRef?: string | null;
    removeRef?: string | null;
    lastDevice?:boolean; recoveryReady?:boolean;revocationComplete?:boolean;
    active?: boolean;
    status?: string;
    category?: string;
    related?: string;
    kind?: string;
    current?: boolean;
    reviewRequired?: boolean;
}
interface Model extends Partial<Item> {
    nextPage?: string | null;
    devices?: Item[];
    requests?: Item[];
    events?: Item[];
    event?: Item;
    verification?: string;
    versions?: Item[];
    passkeys?: {
        active: boolean;
    }[];
    sessions?: {
        current: boolean;
        createdAt: number;
        expiresAt: number;
    }[];
    recoveries?: Item[];
    notifications?: {event: string; createdAt: number}[];
}
function useView(view: string, id?: string, page?: string) { return useQuery({ queryKey: ['view', view, id, page], queryFn: () => api<Model>('web/query', { view, ...(id ? { id } : {}), ...(page ? { page } : {}) }) }); }
function Message({ children, error = false }: {
    children: ReactNode;
    error?: boolean;
}) { return <p role={error ? 'alert' : 'status'} className={error ? 'notice danger' : 'notice'}>{children}</p>; }
function Panel({ title, children }: {
    title: Key;
    children: ReactNode;
}) { const t = useContext(Copy); return <section className="panel"><h2>{t(title)}</h2>{children}</section>; }
function Async({ query, children }: {
    query: ReturnType<typeof useView>;
    children: (data: Model) => ReactNode;
}) { const t = useContext(Copy); if (query.isPending)
    return <div aria-busy="true" className="skeleton"><Message>{t('loading')}</Message></div>; if (query.isError && !query.data)
    return <><Message error>{t(query.error instanceof ApiError && query.error.status === 404 ? 'terminal' : 'error')}</Message><button onClick={() => void query.refetch()}>{t('retry')}</button></>; return <>{query.isRefetchError && <Message error>{t('staleData')}</Message>}{query.data && children(query.data)}</>; }
function Dialog({ title, onClose, children }: {
    title: Key;
    onClose: () => void;
    children: ReactNode;
}) {
    const t = useContext(Copy), ref = useRef<HTMLDivElement>(null);
    useEffect(() => { const previous = document.activeElement as HTMLElement | null; const box = ref.current!; box.querySelector<HTMLElement>('button,a,input')?.focus(); const key = (e: KeyboardEvent) => { if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
    } if (e.key === 'Tab') {
        const f = [...box.querySelectorAll<HTMLElement>('button:not(:disabled),a,input,select,[tabindex="0"]')];
        const first = f[0], last = f.at(-1);
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last?.focus();
        }
        else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first?.focus();
        }
    } }; box.addEventListener('keydown', key); return () => { box.removeEventListener('keydown', key); previous?.focus(); }; }, [onClose]);
    return <div className="overlay"><div ref={ref} role="dialog" aria-modal="true" aria-labelledby="dialog-title" className="dialog"><h2 id="dialog-title">{t(title)}</h2>{children}<button onClick={onClose}>{t('close')}</button></div></div>;
}
function Action({ reference, title, warning, onDone, requiresPasskey = true }: {
    reference?: string | null;
    title: Key;
    warning: Key;
    onDone?: () => void;
    requiresPasskey?: boolean;
}) {
    const t = useContext(Copy), cache = useQueryClient(), [openedRef, setOpenedRef] = useState<string | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<Key | null>(null);
    const stale = openedRef !== reference;
    async function submit() {
        if (!openedRef || stale || busy || error)
            return;
        let executing = false;
        setBusy(true);
        try {
            if (requiresPasskey)
                await stepUp(openedRef);
            executing = true;
            await api('web/execute', { ref: openedRef, confirmed: true });
            await cache.invalidateQueries();
            setOpenedRef(null);
            onDone?.();
        }
        catch (cause) {
            if (cause instanceof PasskeyIncompleteError || (cause instanceof DOMException && ['NotAllowedError', 'AbortError'].includes(cause.name)))
                setError('actionPasskeyIncomplete');
            else if (cause instanceof ApiError && [401, 404, 409, 410].includes(cause.status))
                setError('changed');
            else
                setError(executing ? 'actionOutcomeUnknown' : 'actionUnavailable');
        }
        finally {
            setBusy(false);
        }
    }
    return <><button disabled={!reference} className={title === 'allow' ? 'primary' : ''} onClick={() => { setError(null); setOpenedRef(reference ?? null); }}>{t(title)}</button>{openedRef && <Dialog title={title} onClose={() => {
        if (!busy) {
            setOpenedRef(null);
            if (error && error !== 'actionPasskeyIncomplete')
                void cache.invalidateQueries();
        }
    }}><p>{t(warning)}</p>{(error || (stale && !busy)) && <Message error>{t(error ?? 'changed')}</Message>}<button disabled={busy || stale || !!error} onClick={() => void submit()}>{t(busy ? 'loading' : 'confirm')}</button></Dialog>}</>;
}
function Pages({ next, page, setPage }: {
    next?: string | null;
    page?: string;
    setPage: (p: string | undefined) => void;
}) { const t = useContext(Copy); return next || page ? <div className="tabs">{page && <button onClick={() => setPage(undefined)}>{t('firstPage')}</button>}{next && <button onClick={() => setPage(next)}>{t('nextPage')}</button>}</div> : null; }
function Requests({ items = [] }: {
    items?: Item[];
}) { const t = useContext(Copy); return items.length ? <ul className="cards">{items.map(r => <li key={r.id}><h3>{label(r.action, t, 'saved')}</h3><p>{label(r.state, t, 'pending')}</p><p>{t('agent')} · {date(r.createdAt)}</p><Link to={'/app/requests/' + encodeURIComponent(r.id)}>{t('review')}</Link></li>)}</ul> : <Message>{t('empty')}</Message>; }
function Devices({ items = [] }: {
    items?: Item[];
}) { const t = useContext(Copy); return items.length ? <ul className="cards">{items.map(d => <li key={d.id}><h3>{t('device')} · {d.id.slice(-6)}</h3><p>{label(d.status, t, 'stale')}</p><Link to={'/app/devices/' + encodeURIComponent(d.id)}>{t('details')}</Link></li>)}</ul> : <Message>{t('empty')}</Message>; }
function Events({ items = [] }: {
    items?: Item[];
}) { const t = useContext(Copy); return items.length ? <ul className="rows">{items.map(e => <li key={e.id}><Link to={'/app/activity/' + encodeURIComponent(e.id)}>{label(e.category, t, 'activity')} · {label(e.action, t, 'details')}</Link><time>{date(e.createdAt)}</time></li>)}</ul> : <Message>{t('empty')}</Message>; }
function VerifyBanner({ query, showVerified = false }: { query?: ReturnType<typeof useView>; showVerified?: boolean }) {
    const t = useContext(Copy), activity = useView('activity'), q = query ?? activity, { failed, setFailed } = useContext(Risk);
    const state = q.isError ? 'failed' : q.data?.verification;
    useEffect(() => { if (state === 'failed') setFailed(true); else if (state === 'verified') setFailed(false); }, [state, q.dataUpdatedAt, setFailed]);
    if (state === 'failed' || (failed && state !== 'verified')) return <Message error>{t('verificationFailed')}</Message>;
    if (state === 'pending') return <Message>{t('verificationPending')}</Message>;
    return showVerified && state === 'verified' ? <Message>{t('verified')}</Message> : null;
}
const needsAttention = (d: Item) => !!d.active && ['stale', 'waiting', 'paused', 'unavailable'].includes(d.status ?? 'unavailable');
const isPairingCode = (code: unknown): code is string => typeof code === 'string' && /^(?:[A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{43})$/.test(code);
function pairingReturn(pathname: string, search: string) {
    if (pathname !== '/app/devices/add')
        return undefined;
    const codes = new URLSearchParams(search).getAll('code');
    return codes.length === 1 && isPairingCode(codes[0]) ? codes[0] : undefined;
}
function Shell() {
    const t = useContext(Copy), navigate = useNavigate(), location = useLocation(), cache = useQueryClient(), risk = useContext(Risk), [more, setMore] = useState(false), [error, setError] = useState(false);
    const session = useQuery({ queryKey: ['session'], queryFn: () => api<{
            authenticated: boolean;
        }>('session') });
    const pairingCode = pairingReturn(location.pathname, location.search);
    useEffect(() => { const expired = () => { cache.clear(); risk.setFailed(false); navigate('/sign-in', { replace: true, state: { signInRequired: true, pairingCode } }); }; window.addEventListener('session-expired', expired); return () => window.removeEventListener('session-expired', expired); }, [navigate, cache, risk.setFailed, pairingCode]);
    async function logout() { try {
        await api('logout', {});
        cache.clear();
        risk.setFailed(false);
        navigate('/sign-in', { replace: true });
    }
    catch {
        setError(true);
    } }
    if (session.isPending)
        return <Message>{t('loading')}</Message>;
    if (session.isError && !(session.error instanceof ApiError && session.error.status === 401))
        return <><Message error>{t('error')}</Message><button onClick={() => void session.refetch()}>{t('retry')}</button></>;
    if (session.isError || !session.data?.authenticated)
        return <Navigate to="/sign-in" replace state={{signInRequired:session.isError,pairingCode}}/>;
    const links = (keys: Key[]) => keys.map(k => <NavLink key={k} end={k === 'home'} onClick={() => setMore(false)} to={k === 'home' ? '/app' : '/app/' + k}>{t(k)}</NavLink>);
    return <div className="shell"><aside className="sidebar"><nav aria-label={t('more')}>{links(['home', 'requests', 'devices', 'activity', 'account', 'help'])}<button onClick={() => void logout()}>{t('signOut')}</button></nav><p>{t('noSecrets')}</p></aside><div className="content">{error && <Message error>{t('error')}</Message>}<Outlet /></div><nav className="mobile-nav" aria-label={t('home')}>{links(['home', 'requests', 'devices'])}<button aria-expanded={more} onClick={() => setMore(true)}>{t('more')}</button></nav>{more && <Dialog title="more" onClose={() => setMore(false)}><nav className="sheet-nav">{links(['activity', 'account', 'help'])}<button onClick={() => void logout()}>{t('signOut')}</button></nav></Dialog>}</div>;
}
function Home() { const t = useContext(Copy), q = useView('home'); return <><h1>{t('home')}</h1><p className="lead">{t('promise')}</p><VerifyBanner query={q}/><Async query={q}>{m => <><Panel title="protection"><p className="status">{label(m.status, t, 'unavailable')}</p><Link to="/app/status">{t('status')}</Link></Panel>{!m.devices?.some(d => d.active) && <Panel title="onboarding"><p>{t('onboardingHelp')}</p><Link className="button primary" to="/app/devices/add">{t('add')}</Link></Panel>}<div className="grid"><Panel title="attention"><Requests items={m.requests}/></Panel><Panel title="needsAttention"><Devices items={m.devices?.filter(needsAttention)}/></Panel></div><Panel title="recent"><Events items={m.events?.slice(-6).reverse()}/></Panel></>}</Async></>; }
function RequestList() { const t = useContext(Copy), [recent, setRecent] = useState(false), [page, setPage] = useState<string>(), q = useView(recent ? 'requests-recent' : 'requests', undefined, page); return <><h1>{t('requests')}</h1><VerifyBanner /><div className="tabs" role="tablist" aria-label={t('requests')}><button role="tab" aria-selected={!recent} onClick={() => { setPage(undefined); setRecent(false); }}>{t('attention')}</button><button role="tab" aria-selected={recent} onClick={() => { setPage(undefined); setRecent(true); }}>{t('recent')}</button></div><Async query={q}>{m => <><Requests items={m.requests?.filter(r => recent ? r.state !== 'pending' : r.state === 'pending')}/><Pages next={m.nextPage} page={page} setPage={setPage}/></>}</Async></>; }
function RequestDetail() { const t = useContext(Copy), { requestId } = useParams(), q = useView('request', requestId); return <><h1>{t('review')}</h1><VerifyBanner /><Async query={q}>{m => <><dl className="panel"><dt>{t('action')}</dt><dd>{label(m.action, t, 'saved')}</dd><dt>{t('who')}</dt><dd>{t('agent')}</dd><dt>{t('device')}</dt><dd>{m.deviceId ? <Link to={'/app/devices/' + encodeURIComponent(m.deviceId)}>{t('device')} · {m.deviceId.slice(-6)}</Link> : '—'}</dd><dt>{t('saved')}</dt><dd>{m.itemRef ? <Link to={'/app/history/' + encodeURIComponent(m.itemRef)}>{t('saved')}</Link> : '—'}</dd><dt>{t('when')}</dt><dd>{date(m.createdAt)}</dd><dt>{t('expires')}</dt><dd>{date(m.expiresAt)}</dd><dt>{t('result')}</dt><dd>{label(m.state, t, 'pending')}</dd></dl><Panel title="reason"><p>{t('risk')}</p>{!m.canAllow && m.state === 'pending' && <Message error>{t('missing')}</Message>}</Panel><div className="sticky-actions"><Action reference={m.denyRef} title="deny" warning="confirmAction"/><Action reference={m.canAllow ? m.allowRef : null} title="allow" warning="risk"/></div></>}</Async></>; }
function DeviceList() { const t = useContext(Copy), q = useView('devices'); return <><h1>{t('devices')}</h1><Link className="button primary" to="/app/devices/add">{t('add')}</Link><Async query={q}>{m => <><Panel title="needsAttention"><Devices items={m.devices?.filter(needsAttention)}/></Panel><Panel title="active"><Devices items={m.devices?.filter(d => d.active && !needsAttention(d))}/></Panel><Panel title="removedDevices"><Devices items={m.devices?.filter(d => !d.active)}/></Panel></>}</Async></>; }
function DeviceDetail() { const t = useContext(Copy), { deviceId } = useParams(), q = useView('device', deviceId); return <><h1>{t('device')} · {deviceId?.slice(-6)}</h1><Async query={q}>{d => <div className="panel"><p className="status">{label(d.status, t, 'stale')}</p><p>{t(d.lastDevice?(d.recoveryReady?'lastDeviceWarning':'lastDeviceBlocked'):'removeWarning')}</p>{d.active ? <Action reference={d.removeRef} title="remove" warning={d.lastDevice?'lastDeviceWarning':'removeWarning'}/> : <Message>{t(d.revocationComplete===false?'removePending':'removeDone')}</Message>}</div>}</Async></>; }
function AddDevice() { const t = useContext(Copy), location = useLocation(), [code, setCode] = useState(() => new URLSearchParams(location.search).get('code')?.slice(0, 43) ?? ''), [pair, setPair] = useState<{
    phrase: string;
    confirmRef: string | null;
    requiresDevice: boolean;
} | null>(null), [match, setMatch] = useState(false), [error, setError] = useState(false), [busy, setBusy] = useState(false), nav = useNavigate(); async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setError(false); try {
    setPair(await api('web/pairing', { code }));
    setMatch(false);
}
catch {
    setError(true);
    setPair(null);
}
finally {
    setBusy(false);
} } return <><h1>{t('add')}</h1><CopyLink /><p>{t('pairHelp')}</p><form onSubmit={submit}><label>{t('pairCode')}<input required maxLength={43} value={code} onChange={e => setCode(e.target.value)}/></label><button disabled={busy}>{t(busy ? 'loading' : 'open')}</button></form>{error && <Message error>{t('error')}</Message>}{pair && <section className="panel"><h2>{t('phrase')}</h2><p className="phrase">{pair.phrase}</p><p>{t('mismatch')}</p><label className="checkbox"><input type="checkbox" checked={match} onChange={e => setMatch(e.target.checked)}/>{t('matches')}</label><p>{t(pair.requiresDevice ? 'existingDevice' : 'firstDevice')}</p><Action reference={match ? pair.confirmRef : null} title="confirm" warning="firstDevice" onDone={() => nav('/app/devices')}/><button onClick={() => { setPair(null); setMatch(false); }}>{t('refresh')}</button></section>}<Link to="/recovery">{t('recovery')}</Link></>; }
function Status() { const t = useContext(Copy), q = useView('status'); return <><h1>{t('status')}</h1><Async query={q}>{m => <div className="panel"><p className="status">{label(m.status, t, 'unavailable')}</p><p>{t('statusHelp')}</p><button onClick={() => void q.refetch()}>{t('refresh')}</button></div>}</Async></>; }
function Activity() { const t = useContext(Copy), [page, setPage] = useState<string>(), q = useView('activity', undefined, page), [filter, setFilter] = useState('all'); return <><h1>{t('activity')}</h1><VerifyBanner query={q} showVerified/><label>{t('activity')}<select value={filter} onChange={e => setFilter(e.target.value)}>{(['all', 'credentialUse', 'requests', 'devices', 'accountRecovery', 'problems'] as Key[]).map(k => <option key={k} value={k}>{t(k)}</option>)}</select></label><Async query={q}>{m => <><Events items={m.events?.filter(e => filter === 'all' || (filter === 'credentialUse' && e.category === 'sync') || (filter === 'requests' && e.category === 'approval') || (filter === 'devices' && e.category === 'device') || (filter === 'accountRecovery' && ['account', 'browser', 'recovery'].includes(e.category ?? '')) || (filter === 'problems' && ['rejected', 'counter_risk'].includes(e.action ?? '')))}/><Pages next={m.nextPage} page={page} setPage={setPage}/></>}</Async></>; }
function EventDetail() { const t = useContext(Copy), { eventId } = useParams(), q = useView('event', eventId); return <><h1>{t('event')}</h1><VerifyBanner query={q} showVerified/><Async query={q}>{m => <div className="panel"><p>{label(m.event?.category, t, 'activity')} · {label(m.event?.action, t, 'details')}</p><p>{date(m.event?.createdAt)}</p>{m.event?.category === 'approval' && m.event.related && <p><Link to={'/app/requests/' + encodeURIComponent(m.event.related)}>{t('related')}</Link></p>}{m.event?.deviceId && <Link to={'/app/devices/' + encodeURIComponent(m.event.deviceId)}>{t('device')}</Link>}</div>}</Async></>; }
function History() { const t = useContext(Copy), { itemRef } = useParams(), [page, setPage] = useState<string>(), q = useView('history', itemRef, page); return <><h1>{t('history')}</h1><h2>{t('saved')}</h2><p>{t('historyHelp')}</p><Async query={q}>{m => <><ol className="rows">{m.versions?.map((v, i) => <li key={v.id + i}><strong>{t(v.current ? 'versionCurrent' : 'versionEarlier')}</strong><span>{label(v.kind, t, 'saved')}</span></li>)}</ol><Pages next={m.nextPage} page={page} setPage={setPage}/><Panel title="restore">{m.requests?.length ? <Requests items={m.requests}/> : <Message>{t('waitingRestore')}</Message>}</Panel></>}</Async></>; }
function Account() { const t = useContext(Copy), q = useView('account'); return <><h1>{t('account')}</h1><Async query={q}>{m => <><div className="grid"><Panel title="passkeys"><ul>{m.passkeys?.map((p, i) => <li key={i}>{t('passkeys')} {i + 1} — {t(p.active ? 'enabled' : 'disabled')}</li>)}</ul></Panel><Panel title="sessions"><ul>{m.sessions?.map((s, i) => <li key={i}>{t(s.current ? 'thisSession' : 'otherSession')} · {date(s.createdAt)}</li>)}</ul></Panel></div><Panel title="notifications"><p>{t('notificationsHelp')}</p><ul>{m.notifications?.map((n,i)=><li key={i}>{label(n.event,t,'recovery')} · {date(n.createdAt)}</li>)}</ul><Link to="/app/activity">{t('activity')}</Link></Panel><Panel title="recovery">{m.recoveries?.map(r => <p key={r.id}><Link to={'/recovery/' + encodeURIComponent(r.id)}>{label(r.state, t, 'verifying')}</Link>{r.reviewRequired && <span> · {t('reviewRequired')}</span>}</p>)}<Link to="/recovery">{t('recovery')}</Link><br /><Link to="/app/devices">{t('reviewDevices')}</Link></Panel></>}</Async></>; }
function Help() { const t = useContext(Copy); return <><h1>{t('helpTitle')}</h1><div className="panel"><p>{t('helpText')}</p><h2>{t('passkeys')}</h2><p>{t('helpPasskey')}</p><h2>{t('requests')}</h2><p>{t('helpRequests')}</p><Link to="/recovery">{t('recovery')}</Link></div></>; }
function Public({ title, children }: {
    title: Key;
    children: ReactNode;
}) { const t = useContext(Copy); return <div className="public"><p className="eyebrow">AgentKeychain</p><h1>{t(title)}</h1>{children}</div>; }
function SignIn() { const t = useContext(Copy), location = useLocation(), [email, setEmail] = useState(''), [error, setError] = useState(false), [busy, setBusy] = useState(false), nav = useNavigate(), cache = useQueryClient(); async function submit(e: FormEvent) { e.preventDefault(); if (!supported()) {
    nav('/unsupported-browser');
    return;
} setBusy(true); setError(false); try {
    await api('bootstrap');
    const o = await api<{
        challengeId: string;
        options: Record<string, unknown>;
    }>('authentication/options', { email });
    await api('authentication/verify', { challengeId: o.challengeId, response: await passkey(o.options) });
    cache.clear();
    const code: unknown = location.state?.pairingCode;
    nav(isPairingCode(code) ? '/app/devices/add?code=' + encodeURIComponent(code) : '/app', {replace:true});
}
catch {
    setError(true);
}
finally {
    setBusy(false);
} } return <Public title="signIn">{location.state?.signInRequired === true && <Message error>{t('actionSignIn')}</Message>}<p>{t('promise')}</p><form onSubmit={submit}><label>{t('email')}<input type="email" autoComplete="username webauthn" required value={email} onChange={e => setEmail(e.target.value)} maxLength={254}/></label><button className="primary" disabled={busy}>{t(busy ? 'loading' : 'signIn')}</button></form>{error && <Message error>{t('authError')}</Message>}<p>{t('another')}</p><Link to="/recovery">{t('recovery')}</Link><p>{t('invitation')}</p></Public>; }
function CopyLink() { const t = useContext(Copy), location = useLocation(), [message, setMessage] = useState<Key | null>(null); return <><button onClick={async () => { try {
    await navigator.clipboard.writeText(window.location.origin + location.pathname + location.search + location.hash);
    setMessage('copied');
}
catch {
    setMessage('copyError');
} }}>{t('copy')}</button>{message && <Message>{t(message)}</Message>}</>; }
function JoinPage() { const t = useContext(Copy), { invite = '' } = useParams(), j = useContext(Join), nav = useNavigate(); const q = useQuery({ queryKey: ['invitation', invite], queryFn: async () => { await api('bootstrap'); return api<{
        maskedEmail: string;
    }>('invitation/detail', { invitation: invite }); }, retry: false }); return <Public title="join"><CopyLink />{q.isPending ? <Message>{t('loading')}</Message> : q.isError ? <Message error>{t('inviteError')}</Message> : <><label>{t('invited')}<input readOnly value={q.data.maskedEmail}/></label><button className="primary" onClick={() => { j.setInvite(invite); nav('/verify-email'); }}>{t('verify')}</button></>}</Public>; }
function VerifyEmail() { const t = useContext(Copy), j = useContext(Join), nav = useNavigate(), [email, setEmail] = useState(''), [proof, setProof] = useState(''), [error, setError] = useState(false), [busy, setBusy] = useState(false); if (!j.invite)
    return <Public title="verify"><Message error>{t('inviteError')}</Message></Public>; async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); try {
    await api('bootstrap');
    const r = await api<{
        verificationId: string;
    }>('invitation/verify', { invitation: j.invite, email, proof });
    setProof('');
    j.setVerification(r.verificationId);
    nav('/create-passkey');
}
catch {
    setError(true);
}
finally {
    setBusy(false);
} } return <Public title="verify"><form onSubmit={submit}><label>{t('email')}<input type="email" required maxLength={254} value={email} onChange={e => setEmail(e.target.value)}/></label><SendCode email={email} purpose="invitation" context={j.invite} copy={{send:t('sendCode'),sent:t('codeSent'),error:t('error'),waiting:t('loading')}}/><label>{t('proof')}<input required autoComplete="one-time-code" maxLength={2048} value={proof} onChange={e => setProof(e.target.value)}/></label><button className="primary" disabled={busy}>{t(busy ? 'loading' : 'verify')}</button></form>{error && <Message error>{t('error')}</Message>}</Public>; }
function CreatePasskey() { const t = useContext(Copy), j = useContext(Join), nav = useNavigate(), cache = useQueryClient(), [busy, setBusy] = useState(false), [error, setError] = useState(false); async function create() { if (!supported()) {
    nav('/unsupported-browser');
    return;
} setBusy(true); try {
    const o = await api<{
        challengeId: string;
        userId: string;
        options: Record<string, unknown>;
    }>('registration/options', { verificationId: j.verificationId });
    await api('registration/verify', { challengeId: o.challengeId, userId: o.userId, response: await passkey(o.options, true) });
    j.setInvite('');
    j.setVerification('');
    cache.clear();
    nav('/app');
}
catch {
    setError(true);
}
finally {
    setBusy(false);
} } return <Public title="create">{j.verificationId ? <button className="primary" disabled={busy} onClick={() => void create()}>{t(busy ? 'loading' : 'create')}</button> : <Message error>{t('inviteError')}</Message>}{error && <Message error>{t('authError')}</Message>}</Public>; }
function Recovery() { const t = useContext(Copy), [email, setEmail] = useState(''), [proof, setProof] = useState(''), [requestRef, setRef] = useState(() => { const ref = new URLSearchParams(window.location.hash.slice(1)).get('requestRef') ?? ''; return /^[A-Za-z0-9_-]{43}$/.test(ref) ? ref : ''; }), [busy, setBusy] = useState(false), [message, setMessage] = useState<Key | null>(null), nav = useNavigate(); async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); try {
    await api('bootstrap');
    await api('recovery/verify', { email, proof, requestRef });
    setProof('');
    setMessage('recoveryAccepted');
    try {
        const r = await api<{
            id: string;
        }>('recovery/start', {});
        nav('/recovery/' + encodeURIComponent(r.id));
    }
    catch { /* An ineligible attempt has the same verification message. */ }
}
catch {
    setMessage('error');
}
finally {
    setBusy(false);
} } return <Public title="recovery"><p>{t('recoveryHelp')}</p><form onSubmit={submit}><label>{t('email')}<input type="email" required maxLength={254} value={email} onChange={e => setEmail(e.target.value)}/></label><SendCode email={email} purpose="recovery" context={requestRef} copy={{send:t('sendCode'),sent:t('codeSent'),error:t('error'),waiting:t('loading')}}/><label>{t('proof')}<input required autoComplete="one-time-code" maxLength={2048} value={proof} onChange={e => setProof(e.target.value)}/></label><label>{t('recoveryCode')}<input required maxLength={43} value={requestRef} onChange={e => setRef(e.target.value)}/></label><button className="primary" disabled={busy}>{t(busy ? 'loading' : 'verifyAccount')}</button></form>{message && <Message error={message === 'error'}>{t(message)}</Message>}<Link to="/sign-in">{t('signIn')}</Link></Public>; }
function RecoveryCase() {
    const t = useContext(Copy), { caseId } = useParams(), cache = useQueryClient();
    const [confirmationRef, setConfirmation] = useState(''), [confirming, setConfirming] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState(false);
    const session = useQuery({ queryKey: ['recovery-session'], queryFn: async () => { try {
            return (await api<{
                authenticated: boolean;
            }>('session')).authenticated;
        }
        catch {
            return false;
        } } });
    const controls = useQuery({ queryKey: ['recovery-controls', caseId], enabled: session.data === true, queryFn: () => api<{
            cancelRef: string | null;
            reviewRef: string | null;
        }>('web/query', { view: 'recovery', id: caseId }) });
    const q = useQuery({ queryKey: ['recovery', caseId, session.data], enabled: !session.isPending, queryFn: () => api<{
            id: string;
            state: string;
            reviewRequired: boolean;
        }>(session.data ? 'web/query' : 'recovery/status', session.data ? {view:'recovery', id:caseId} : { id: caseId }) });
    async function cancel() { setBusy(true); setError(false); try {
        if (session.data) {
            if (!controls.data?.cancelRef)
                throw new Error('Unavailable');
            await stepUp(controls.data.cancelRef);
        }
        const result = session.data ? await api('web/execute', {ref:controls.data!.cancelRef, confirmed:true, confirmationRef}) : await api('recovery/cancel', { id: caseId, confirmed: true, confirmationRef });
        if ('state' in result)
            cache.setQueryData(['recovery', caseId, session.data], result);
        else
            await q.refetch();
        setConfirming(false);
        setConfirmation('');
    }
    catch {
        setError(true);
    }
    finally {
        setBusy(false);
    } }
    return <Public title="recovery">{q.isPending ? <Message>{t('loading')}</Message> : q.isError ? <><Message error>{t('error')}</Message><p>{t('relogin')}</p><Link to="/recovery">{t('verifyAccount')}</Link></> : <><ol className="steps">{(['verifying', 'prepared', 'confirmed', 'released', 'completed'] as Key[]).map(stage => <li key={stage} aria-current={q.data.state === stage ? 'step' : undefined}>{t(stage)}</li>)}</ol><Message>{label(q.data.state, t, 'verifying')}</Message>{q.data.state === 'completed' ? <><p>{t('relogin')}</p><Link to="/app/devices">{t('reviewDevices')}</Link>{q.data.reviewRequired && controls.data?.reviewRef && <Action reference={controls.data.reviewRef} title="reviewDevices" warning="relogin" onDone={() => void q.refetch()}/>}<Link to="/sign-in">{t('signIn')}</Link></> : !['cancelled', 'expired', 'activating'].includes(q.data.state) ? <><p>{t('cancelHelp')}</p><label>{t('cancelCode')}<input value={confirmationRef} onChange={e => setConfirmation(e.target.value)} maxLength={43}/></label><button disabled={confirmationRef.length !== 43} onClick={() => setConfirming(true)}>{t('cancelRecovery')}</button></> : null}</>}{confirming && <Dialog title="cancelRecovery" onClose={() => { if (!busy)
        setConfirming(false); }}><p>{t('cancelHelp')}</p>{error && <Message error>{t('error')}</Message>}<button disabled={busy} onClick={() => void cancel()}>{t(busy ? 'loading' : 'confirm')}</button></Dialog>}<button disabled={q.data?.state === 'cancelled'} onClick={() => void q.refetch()}>{t('refresh')}</button></Public>;
}
export function App() { const [language, setLanguage] = useState<'en' | 'zh'>('en'), [invite, setInvite] = useState(''), [verificationId, setVerification] = useState(''), [failed, setFailed] = useState(false), location = useLocation(); const t = (key: Key) => language === 'en' ? en[key] : zh[key]; useEffect(() => { document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN'; document.title = 'AgentKeychain'; }, [language]); useEffect(() => { const heading = document.querySelector<HTMLElement>('h1'); if (heading) {
    heading.tabIndex = -1;
    heading.focus();
} }, [location.pathname]); return <Copy.Provider value={t}><Risk.Provider value={{ failed, setFailed }}><Join.Provider value={{ invite, verificationId, setInvite, setVerification }}><a className="skip" href="#main">{t('skip')}</a><header><Link className="wordmark" to="/app">AgentKeychain<span>Cloud</span></Link><label className="language">{t('language')}<select value={language} onChange={e => setLanguage(e.target.value as 'en' | 'zh')}><option value="en">English</option><option value="zh">简体中文</option></select></label></header><main id="main"><Routes><Route path="/sign-in" element={<SignIn />}/><Route path="/join/:invite" element={<JoinPage />}/><Route path="/verify-email" element={<VerifyEmail />}/><Route path="/create-passkey" element={<CreatePasskey />}/><Route path="/recovery" element={<Recovery />}/><Route path="/recovery/:caseId" element={<RecoveryCase />}/><Route path="/unsupported-browser" element={<Public title="unsupported"><p>{t('unsupportedHelp')}</p><Link to="/sign-in">{t('back')}</Link></Public>}/><Route path="/app" element={<Shell />}><Route index element={<Home />}/><Route path="requests" element={<RequestList />}/><Route path="requests/:requestId" element={<RequestDetail />}/><Route path="devices" element={<DeviceList />}/><Route path="devices/add" element={<AddDevice />}/><Route path="devices/:deviceId" element={<DeviceDetail />}/><Route path="status" element={<Status />}/><Route path="activity" element={<Activity />}/><Route path="activity/:eventId" element={<EventDetail />}/><Route path="history/:itemRef" element={<History />}/><Route path="account" element={<Account />}/><Route path="help" element={<Help />}/></Route><Route path="/" element={<Navigate to="/sign-in" replace/>}/><Route path="*" element={<Public title="notFound"><Link to="/sign-in">{t('back')}</Link></Public>}/></Routes></main></Join.Provider></Risk.Provider></Copy.Provider>; }
