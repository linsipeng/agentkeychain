import {afterEach,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen} from '@testing-library/react';
import {SendCode} from '../src/SendCode';
import {api} from '../src/api';
vi.mock('../src/api',()=>({api:vi.fn()}));
const copy={send:'Send verification code',sent:'Check your email if eligible.',error:'Try again.',waiting:'Sending…'};
afterEach(()=>{cleanup();vi.useRealTimers();vi.resetAllMocks();});
it('starts its cooldown when the response arrives, not when clicked',async()=>{
 vi.useFakeTimers();let resolve!:(v:{accepted:boolean;retryAfter:number})=>void;vi.mocked(api).mockResolvedValueOnce({authenticated:false}).mockImplementation(()=>new Promise(r=>{resolve=r as typeof resolve;}));
 render(<SendCode email="person@example.com" purpose="recovery" context="ref" copy={copy}/>);
 fireEvent.click(screen.getByRole('button'));await act(()=>vi.advanceTimersByTimeAsync(10000));expect(screen.getByRole('button').textContent).toBe('Sending…');
 await act(async()=>resolve({accepted:true,retryAfter:60}));expect(vi.mocked(api).mock.calls[0]?.[0]).toBe('bootstrap');expect(vi.mocked(api).mock.calls[1]?.[0]).toBe('email/request');expect(screen.getByRole('button').textContent).toContain('(60)');expect(screen.getByRole('status').textContent).toBe(copy.sent);
 await act(()=>vi.advanceTimersByTimeAsync(60000));expect(screen.getByRole('button').hasAttribute('disabled')).toBe(false);
});
it('shows generic failure and allows retry without a false cooldown',async()=>{vi.mocked(api).mockRejectedValue(new Error('private provider error'));render(<SendCode email="person@example.com" purpose="invitation" context="invite" copy={copy}/>);await act(async()=>fireEvent.click(screen.getByRole('button')));expect(screen.getByRole('status').textContent).toBe(copy.error);expect(screen.getByRole('button').hasAttribute('disabled')).toBe(false);});
