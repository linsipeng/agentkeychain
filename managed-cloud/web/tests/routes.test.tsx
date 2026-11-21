import { beforeEach, afterEach, expect, test, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { App } from '../src/App';
let calls: {
    route: string;
    body: Record<string, unknown>;
}[];
let verification = 'verified';
let fail = false;
let deviceActive = true;
let lastDevice=false,recoveryReady=false,removalComplete=true;
let deviceStatus = 'stale';
let requestState = 'pending';
let requestComplete = true;
let session = true;
let authAccepted = true;
let recoveryState = 'prepared';
let actionFailure: { route: string; status: number } | undefined;
const device = () => ({ id: 'device-one', active: deviceActive, status: deviceActive ? deviceStatus : 'removed', lastDevice,recoveryReady,revocationComplete:!deviceActive&&removalComplete,removeRef: deviceActive&&(!lastDevice||recoveryReady) ? 'remove-reference' : null });
const request = () => ({ id: 'request-one', action: 'delete', state: requestState, deviceId: 'device-one', itemRef: 'item-one', createdAt: 1700000000, expiresAt: 1999999999, canAllow: requestComplete && requestState === 'pending', allowRef: requestComplete ? 'allow-reference' : null, denyRef: 'deny-reference' });
const event = { id: 'event-one', category: 'device', action: 'approved', createdAt: 1700000000, deviceId: 'device-one' };
beforeEach(() => {
    calls = [];
    verification = 'verified';
    fail = false;
    deviceActive = true;lastDevice=false;recoveryReady=false;removalComplete=true;
    deviceStatus = 'stale';
    requestState = 'pending';
    requestComplete = true;
    session = true;
    authAccepted = true;
    recoveryState = 'prepared';
    actionFailure = undefined;
    document.cookie = '__Host-akc_csrf=synthetic; Secure; Path=/';
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
        const route = url.replace('/v1/auth/', ''), body = init.body ? JSON.parse(init.body as string) : {};
        calls.push({ route, body });
        if (actionFailure?.route === route)
            return Response.json({ error: { message: 'synthetic internal diagnostic' } }, { status: actionFailure.status });
        if (fail && route === 'web/query')
            return Response.json({ error: {} }, { status: 503 });
        if (route === 'session')
            return session ? Response.json({ authenticated: true }) : Response.json({error:{}},{status:401});
        if (route === 'bootstrap/v2')
            return Response.json({ authenticated: false });
        if (route === 'logout') {
            session = false;
            return Response.json({ ok: true });
        }
        if (route === 'authentication/options' || route === 'registration/options')
            return Response.json({ challengeId: 'challenge-one', userId: 'dXNlcg', options: route === 'registration/options' ? { challenge: 'AA', rp: { id: 'local.invalid', name: 'AgentKeychain' }, user: { id: 'dXNlcg', name: 'synthetic', displayName: 'synthetic' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none' } : { challenge: 'AA', rpId: 'local.invalid', userVerification: 'required' } });
        if (route === 'authentication/verify' || route === 'registration/verify')
            return authAccepted ? Response.json({ authenticated: true }) : Response.json({ error: { code: 'unauthorized' } }, { status: 401 });
        if (route === 'web/options')
            return Response.json({ challengeId: 'challenge-one', options: { challenge: 'AA', rpId: 'local.invalid', userVerification: 'required' } });
        if (route === 'web/verify')
            return Response.json({ authenticated: true });
        if (route === 'web/execute') {
            if (body.ref === 'cancel-reference') { recoveryState='cancelled'; return Response.json({id:'case-one',state:recoveryState,reviewRequired:true}); }
            if (body.ref === 'remove-reference')
                deviceActive = false;
            if (body.ref === 'allow-reference')
                requestState = 'approved';
            if (body.ref === 'deny-reference')
                requestState = 'denied';
            return Response.json({ removed: !deviceActive, state: requestState });
        }
        if (route === 'web/pairing')
            return Response.json({ phrase: 'amber birch cloud', confirmRef: 'pair-reference', requiresDevice: false });
        if (route === 'invitation/detail')
            return Response.json({ maskedEmail: 's***@e***.invalid', status: 'available' });
        if (route === 'invitation/verify')
            return Response.json({ verificationId: 'verification-one' });
        if (route === 'recovery/status')
            return Response.json({ id: 'case-one', state: recoveryState, reviewRequired: true });
        if (route === 'recovery/cancel') {
            recoveryState = 'cancelled';
            return Response.json({ id: 'case-one', state: 'cancelled', reviewRequired: true });
        }
        if (route === 'web/query') {
            const m: Record<string, unknown> = { recovery:{id:'case-one',state:recoveryState,reviewRequired:true,cancelRef:'cancel-reference',reviewRef:'review-reference'}, home: { devices: [device()], requests: [request()], events: [event], status: 'stale', verification }, devices: { devices: [device()] }, device: device(), requests: { requests: [request()] }, request: request(), activity: { events: [event], verification }, event: { event, verification }, status: { status: 'stale' }, history: { versions: [{ id: 'version-a', kind: 'delete', current: true }, { id: 'version-b', kind: 'put', current: false }], requests: [] }, account: { notifications:[{event:'started',createdAt:1700000000}], passkeys: [{ active: true }], sessions: [{ current: true, createdAt: 1700000000 }], recoveries: [] } };
            return Response.json(m[body.view] ?? {});
        }
        return Response.json({ error: {} }, { status: 401 });
    }));
    vi.stubGlobal('PublicKeyCredential', class {
    });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: vi.fn(async () => ({ id: 'new-credential', rawId: new Uint8Array([1]).buffer, getClientExtensionResults: () => ({}), response: { clientDataJSON: new Uint8Array([1]).buffer, attestationObject: new Uint8Array([2]).buffer, getTransports: () => ['internal'] } })), get: vi.fn(async () => ({ id: 'credential', rawId: new Uint8Array([1]).buffer, type: 'public-key', getClientExtensionResults: () => ({}), response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([2]).buffer, signature: new Uint8Array([3]).buffer, userHandle: null } })) } });
});
afterEach(() => vi.unstubAllGlobals());
function mount(path: string) { const cache = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } }); return { cache, ...render(<QueryClientProvider client={cache}><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></QueryClientProvider>) }; }
const paths = ['/sign-in', '/join/synthetic-invitation', '/verify-email', '/create-passkey', '/recovery', '/recovery/case-one', '/unsupported-browser', '/app', '/app/requests', '/app/requests/request-one', '/app/devices', '/app/devices/add', '/app/devices/device-one', '/app/status', '/app/activity', '/app/activity/event-one', '/app/history/item-one', '/app/account', '/app/help'];
test.each(paths)('route %s has one heading and zero serious/critical axe findings', async (path) => {
    const { container } = mount(path);
    await screen.findByRole('heading', { level: 1 });
    await waitFor(() => expect(container.querySelector('[aria-busy=true]')).toBeNull());
    expect(container.querySelectorAll('h1')).toHaveLength(1);
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(result.violations.filter(v => ['serious', 'critical'].includes(v.impact ?? ''))).toEqual([]);
    expect(container.textContent).not.toMatch(/ciphertext|nonce|digest|Worker|bearer token|key package/);
});
test('missing request details disable allow; no batch approval exists', async () => { requestComplete = false; mount('/app/requests/request-one'); await screen.findByText('Some details are missing. You cannot allow this request. Review it on your device.'); expect((screen.getByRole('button', { name: 'Allow once' }) as HTMLButtonElement).disabled).toBe(true); expect(screen.queryByRole('checkbox')).toBeNull(); });
test.each(['Allow once', 'Don’t allow'])('%s performs exact step-up then mutation and authoritative readback', async (name) => { mount('/app/requests/request-one'); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name })); const dialog = screen.getByRole('dialog'); await user.click(within(dialog).getByRole('button', { name: 'Confirm' })); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()); const relevant = calls.filter(c => ['web/options', 'web/verify', 'web/execute'].includes(c.route)); expect(relevant.map(c => c.route)).toEqual(['web/options', 'web/verify', 'web/execute']); expect(new Set(relevant.map(c => c.body.ref)).size).toBe(1); expect(calls.filter(c => c.route === 'web/query' && c.body.view === 'request').length).toBeGreaterThan(1); });
test.each([
    ['web/options', 503, 'Confirmation is temporarily unavailable. Close this dialog and check the request later.', 0],
    ['web/options', 404, 'The request changed or is no longer available. Review it again.', 0],
    ['web/execute', 503, 'The result could not be confirmed. Close this dialog and check the latest status before trying again.', 1],
] as const)('separates %s status %s from other failures without replay', async (route, status, message, executes) => {
    actionFailure = { route, status };
    mount('/app/requests/request-one');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Allow once' }));
    const dialog = within(screen.getByRole('dialog'));
    const confirm = dialog.getByRole('button', { name: 'Confirm' }) as HTMLButtonElement;
    await user.click(confirm);
    expect((await dialog.findByRole('alert')).textContent).toBe(message);
    expect(confirm.disabled).toBe(true);
    await user.click(confirm);
    expect(calls.filter(c => c.route === 'web/execute')).toHaveLength(executes);
    expect(screen.queryByText('synthetic internal diagnostic')).toBeNull();
});
test('leaves a sign-in notice after the approval session is rejected', async () => {
    actionFailure = { route: 'web/options', status: 401 };
    mount('/app/requests/request-one');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Allow once' }));
    session = false;
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }));
    await screen.findByText('Sign in again before continuing.');
    expect(calls.filter(c => c.route === 'web/execute')).toHaveLength(0);
});
test('action rejection leaves a still-authenticated user in the app without replay', async () => {
    actionFailure = { route: 'web/options', status: 401 };
    mount('/app/requests/request-one');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Allow once' }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }));
    await screen.findByText('The request changed or is no longer available. Review it again.');
    expect(screen.queryByRole('heading', {name:'Sign in with passkey'})).toBeNull();
    expect(calls.filter(c=>c.route === 'session')).toHaveLength(2);
    expect(calls.filter(c=>c.route === 'web/execute')).toHaveLength(0);
});
test('session 503 offers a retry instead of sending the user into a login loop', async () => {
    actionFailure = {route:'session',status:503};
    mount('/app');
    const retry=await screen.findByRole('button',{name:'Try again'});
    expect(screen.queryByRole('heading', {name:'Sign in with passkey'})).toBeNull();
    actionFailure=undefined;
    await userEvent.click(retry);
    await screen.findByRole('heading',{name:'Home',level:1});
    expect(calls.filter(c=>c.route==='authentication/verify')).toHaveLength(0);
});
test('sign-in returns to the CLI pairing route with its valid code, without auto-approving', async () => {
    session = false;
    mount('/app/devices/add?code=pairing-code');
    const user=userEvent.setup();
    await screen.findByRole('heading',{name:'Sign in with passkey'});
    session = true;
    await user.type(screen.getByLabelText('Email address'),'synthetic@example.invalid');
    await user.click(screen.getByRole('button',{name:'Sign in with passkey'}));
    await waitFor(()=>expect(screen.getByDisplayValue('pairing-code')).toBeTruthy());
    expect(calls.filter(c=>c.route.startsWith('web/') && c.route!=='web/query')).toHaveLength(0);
});
test.each(['pairing-code&code=another-code', 'incorrect-length'])('does not forward an invalid or ambiguous pairing parameter %s',async query=>{
    session=false;
    mount('/app/devices/add?code='+query);
    const user=userEvent.setup();
    await screen.findByRole('heading',{name:'Sign in with passkey'});
    session=true;
    await user.type(screen.getByLabelText('Email address'),'synthetic@example.invalid');
    await user.click(screen.getByRole('button',{name:'Sign in with passkey'}));
    await screen.findByRole('heading',{name:'Home',level:1});
    expect(calls.filter(c=>c.route==='web/pairing')).toHaveLength(0);
});
test('an interrupted passkey prompt does not verify or execute the action', async () => {
    vi.mocked(navigator.credentials.get).mockRejectedValueOnce(new DOMException('synthetic browser detail', 'NotAllowedError'));
    mount('/app/requests/request-one');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Allow once' }));
    const dialog = within(screen.getByRole('dialog'));
    await user.click(dialog.getByRole('button', { name: 'Confirm' }));
    await dialog.findByText('Passkey confirmation did not finish. No action was submitted. Close this dialog to try again when ready.');
    expect(calls.filter(c => ['web/verify', 'web/execute'].includes(c.route))).toHaveLength(0);
    expect(screen.queryByText('synthetic browser detail')).toBeNull();
});
test('device removal requires confirmation and server readback before removed state', async () => { mount('/app/devices/device-one'); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Remove device' })); expect(deviceActive).toBe(true); await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' })); await screen.findByText('Device removal confirmed.'); expect(calls.filter(c => c.body.view === 'device').length).toBeGreaterThan(1); });
test('pair phrase mismatch disables confirmation', async () => { mount('/app/devices/add'); const user = userEvent.setup(); await user.type(await screen.findByLabelText('Code from your device'), 'abc123abc123'); await user.click(screen.getByRole('button', { name: 'Open' })); await screen.findByText('amber birch cloud'); expect((screen.getByRole('button', { name: 'Confirm' }) as HTMLButtonElement).disabled).toBe(true); await user.click(screen.getByRole('checkbox')); expect((screen.getByRole('button', { name: 'Confirm' }) as HTMLButtonElement).disabled).toBe(false); });
test('activity verification failure persists on home and requests', async () => { verification = 'failed'; mount('/app'); await screen.findByText('Activity could not be verified. Do not rely on these records until verification succeeds.'); const user = userEvent.setup(); await user.click(screen.getAllByRole('link', { name: 'Requests' })[0]); await screen.findByText('Activity could not be verified. Do not rely on these records until verification succeeds.'); });
test('mobile More starts closed; Escape restores trigger focus', async () => { mount('/app'); const user = userEvent.setup(); const more = await screen.findByRole('button', { name: 'More' }); expect(screen.queryByRole('dialog')).toBeNull(); await user.click(more); expect(screen.getByRole('dialog')).toBeTruthy(); await user.keyboard('{Escape}'); expect(screen.queryByRole('dialog')).toBeNull(); expect(document.activeElement).toBe(more); });
test('logout clears cached authenticated data and redirects', async () => { const { cache } = mount('/app'); const user = userEvent.setup(); await user.click(await screen.findByRole('button', { name: 'Sign out' })); await screen.findByRole('heading', { name: 'Sign in with passkey' }); expect(cache.getQueryCache().findAll({ queryKey: ['view'] })).toHaveLength(0); });
test('retryable errors expose retry and do not claim success', async () => { fail = true; mount('/app/status'); await screen.findByRole('button', { name: 'Try again' }); expect(screen.queryByText('Everything is up to date')).toBeNull(); fail = false; await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' })); await screen.findByText('Not recently checked'); });
test('language changes all route copy; history keeps deleted current version', async () => { mount('/app/history/item-one'); await screen.findByText('Delete saved credential'); const user = userEvent.setup(); await user.selectOptions(screen.getByRole('combobox'), 'zh'); await screen.findByRole('heading', { name: '早期版本', level: 1 }); expect(screen.getByText('当前版本')).toBeTruthy(); expect(screen.getByText('等待设备准备请求')).toBeTruthy(); });
test('invitation displays authoritative mask then requires email and proof', async () => { mount('/join/synthetic-invitation'); const user = userEvent.setup(); const field = await screen.findByLabelText('Invited email') as HTMLInputElement; expect(field.readOnly).toBe(true); expect(field.value).toBe('s***@e***.invalid'); await user.click(screen.getByRole('button', { name: 'Verify email' })); await user.type(screen.getByLabelText('Email address'), 'synthetic@example.invalid'); await user.type(screen.getByLabelText('Email verification code'), 'synthetic-proof'); await user.click(screen.getByRole('button', { name: 'Verify email' })); await screen.findByRole('heading', { name: 'Create a passkey' }); expect(calls.find(c => c.route === 'invitation/verify')?.body).toEqual({ invitation: 'synthetic-invitation', email: 'synthetic@example.invalid', proof: 'synthetic-proof' }); });
test('invitation through passkey creation reaches Home using exact registration options and response', async () => {
    mount('/join/synthetic-invitation');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Verify email' }));
    await user.type(screen.getByLabelText('Email address'), 'synthetic@example.invalid');
    await user.type(screen.getByLabelText('Email verification code'), 'synthetic-proof');
    await user.click(screen.getByRole('button', { name: 'Verify email' }));
    await user.click(await screen.findByRole('button', { name: 'Create a passkey' }));
    await screen.findByRole('heading', { name: 'Home', level: 1 });
    expect(navigator.credentials.create).toHaveBeenCalledWith(expect.objectContaining({ publicKey: expect.objectContaining({ challenge: new Uint8Array([0]), attestation: 'none' }) }));
    const sent = calls.find(c => c.route === 'registration/verify')!.body;
    expect(Object.keys(sent).sort()).toEqual(['challengeId', 'response', 'userId']);
});
test.each(['success', 'cancel', 'unknown'])('passkey sign-in %s has truthful outcome', async (mode) => {
    if (mode === 'cancel')
        vi.mocked(navigator.credentials.get).mockRejectedValueOnce(new DOMException('Cancelled', 'NotAllowedError'));
    if (mode === 'unknown')
        authAccepted = false;
    mount('/sign-in');
    const user = userEvent.setup();
    await user.type(screen.getByLabelText('Email address'), 'synthetic@example.invalid');
    await user.click(screen.getByRole('button', { name: 'Sign in with passkey' }));
    if (mode === 'success')
        await screen.findByRole('heading', { name: 'Home', level: 1 });
    else {
        await screen.findByText('We couldn’t verify this attempt. Try again with your passkey.');
        expect(screen.queryByRole('heading', { name: 'Home' })).toBeNull();
    }
});
test('confirmation dialog traps keyboard focus and passes axe', async () => {
    const { container } = mount('/app/devices/device-one');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Remove device' }));
    const dialog = screen.getByRole('dialog');
    const close = within(dialog).getByRole('button', { name: 'Close' });
    close.focus();
    await user.keyboard('{Tab}');
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Confirm' }));
    const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(result.violations.filter(v => ['serious', 'critical'].includes(v.impact ?? ''))).toEqual([]);
});
test('copy invitation preserves complete URL', async () => {
    const user = userEvent.setup();
    mount('/join/full-synthetic-capability');
    const write = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy complete link' }));
    expect(write).toHaveBeenCalledWith('https://local.invalid/join/full-synthetic-capability');
});
test('restricted recovery cancellation uses independent confirmation and persisted readback', async () => {
    session = false;
    mount('/recovery/case-one');
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Cancellation confirmation from your device'), 'c'.repeat(43));
    await user.click(screen.getByRole('button', { name: 'Cancel recovery' }));
    expect(recoveryState).toBe('prepared');
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }));
    await screen.findByText('Cancelled');
    expect(calls.find(c => c.route === 'recovery/cancel')?.body).toEqual({ id: 'case-one', confirmed: true, confirmationRef: 'c'.repeat(43) });
});
test.each(['activating', 'completed', 'cancelled', 'expired'])('recovery %s cannot offer cancellation', async (state) => {
    recoveryState = state; session=false;
    mount('/recovery/case-one');
    await screen.findByRole('heading', { name: 'Recover access' });
    await waitFor(() => expect(calls.some(c => c.route === 'recovery/status')).toBe(true));
    expect(screen.queryByRole('button', { name: 'Cancel recovery' })).toBeNull();
    if (state === 'completed')
        await screen.findByText('Sign in again with a passkey and review your devices before continuing.');
});

test.each(['/app','/app/requests','/app/activity','/app/activity/event-one'])('verification transitions are consistent on %s',async path=>{
    verification='failed'; const {cache}=mount(path);
    await screen.findAllByText('Activity could not be verified. Do not rely on these records until verification succeeds.');
    expect(screen.queryByText('Activity verification pending')).toBeNull();
    verification='pending'; await act(async()=>{await cache.invalidateQueries();});
    expect(screen.queryByText('Activity verified')).toBeNull();
    expect(screen.queryByText('Activity verification pending')).toBeNull();
    expect(screen.getByRole('alert')).toBeTruthy();
    verification='verified'; await act(async()=>{await cache.invalidateQueries();});
    await waitFor(()=>expect(screen.queryByText('Activity could not be verified. Do not rely on these records until verification succeeds.')).toBeNull());
    expect(screen.queryByText('Activity verification pending')).toBeNull();
});
test('session expiration clears account A risk and queries before account B signs in',async()=>{
    verification='failed';const {cache}=mount('/app');
    await screen.findByRole('alert');
    session=false; await act(async()=>{await cache.invalidateQueries({queryKey:['session']});});
    await screen.findByRole('heading',{name:'Sign in with passkey'});
    await waitFor(()=>expect(cache.getQueryCache().getAll()).toHaveLength(0));
    verification='pending'; session=true; const user=userEvent.setup();
    await user.type(screen.getByLabelText('Email address'),'different@example.invalid');
    await user.click(screen.getByRole('button',{name:'Sign in with passkey'}));
    await screen.findByRole('heading',{name:'Home',level:1});
    await screen.findByText('Activity verification pending');
    expect(screen.queryByRole('alert')).toBeNull();
});
test('Requests exposes attention and recent tabs and changes the queried view',async()=>{
    mount('/app/requests');const user=userEvent.setup();
    const attention=await screen.findByRole('tab',{name:'Needs your attention'});
    expect(attention.getAttribute('aria-selected')).toBe('true');
    const recent=screen.getByRole('tab',{name:'Recent'});await user.click(recent);
    await waitFor(()=>expect(calls.some(c=>c.body.view==='requests-recent')).toBe(true));
    expect(recent.getAttribute('aria-selected')).toBe('true');
});
test('Devices has truthful attention, active and removed sections',async()=>{
    mount('/app/devices');
    await screen.findByRole('heading',{name:'Needs attention'});
    expect(screen.getByRole('heading',{name:'Active devices'})).toBeTruthy();
    expect(screen.getByRole('heading',{name:'Removed devices'})).toBeTruthy();
    expect(screen.queryByText('Everything is up to date')).toBeNull();
});

test('Account shows notification status and recorded recovery events without delivery claims or settings',async()=>{
    mount('/app/account');
    await screen.findByRole('heading',{name:'Notification status'});
    expect(screen.getByText(/^Recovery started/)).toBeTruthy();
    expect(screen.getByText('Notification delivery status is unavailable here. Check Activity for recorded account and recovery events.')).toBeTruthy();
    expect(screen.queryByRole('checkbox')).toBeNull();
});

test.each(['/app','/app/requests','/app/activity','/app/activity/event-one'])('initial pending is not failed on %s',async path=>{verification='pending';mount(path);await screen.findByText('Activity verification pending');expect(screen.queryByRole('alert')).toBeNull();});

test.each(['current','updating','waiting','stale','paused','unavailable','removed'])('device %s appears in exactly one section',async status=>{
    deviceStatus=status;deviceActive=status!=='removed';mount('/app/devices');
    await screen.findByRole('heading',{name:'Needs attention'});
    expect(screen.getAllByRole('link',{name:'Details'})).toHaveLength(1);
    const heading=screen.getByRole('heading',{name:status==='removed'?'Removed devices':['current','updating'].includes(status)?'Active devices':'Needs attention'});
    expect(within(heading.parentElement!).getByRole('link',{name:'Details'})).toBeTruthy();
});

test('account recovery uses only safe web query and cancellation action contracts',async()=>{
    mount('/recovery/case-one');const user=userEvent.setup();
    await user.type(await screen.findByLabelText('Cancellation confirmation from your device'),'c'.repeat(43));
    await user.click(screen.getByRole('button',{name:'Cancel recovery'}));
    await user.click(within(screen.getByRole('dialog')).getByRole('button',{name:'Confirm'}));
    await screen.findByText('Cancelled');
    expect(calls.filter(c=>c.route.startsWith('recovery/'))).toEqual([]);
    expect(calls.find(c=>c.route==='web/execute')?.body).toEqual({ref:'cancel-reference',confirmed:true,confirmationRef:'c'.repeat(43)});
    expect(calls.some(c=>c.route==='web/query'&&c.body.view==='recovery')).toBe(true);
});

test('last device without recovery is non-removable and explains how to retain access',async()=>{
 lastDevice=true;mount('/app/devices/device-one');
 expect((await screen.findByRole('button',{name:'Remove device'})).hasAttribute('disabled')).toBe(true);
 await screen.findByText(/Add another trusted device or prepare recovery/);
 expect(calls.some(c=>c.route==='web/execute')).toBe(false);
});
test('last device with recovery requires the recovery warning before step-up and readback',async()=>{
 lastDevice=true;recoveryReady=true;mount('/app/devices/device-one');const user=userEvent.setup();
 await user.click(await screen.findByRole('button',{name:'Remove device'}));
 expect(within(screen.getByRole('dialog')).getByText(/Access will require recovery after removal/)).toBeTruthy();
 expect(deviceActive).toBe(true);
 await user.click(within(screen.getByRole('dialog')).getByRole('button',{name:'Confirm'}));
 await screen.findByText('Device removal confirmed.');expect(calls.filter(c=>c.body.view==='device').length).toBeGreaterThan(1);
});

test('enforced removal does not claim completion before independent witness readback',async()=>{
 deviceActive=false;removalComplete=false;mount('/app/devices/device-one');
 await screen.findByText('Access has been blocked. Independent confirmation of removal is still pending.');
 expect(screen.queryByText('Device removal confirmed.')).toBeNull();
});
