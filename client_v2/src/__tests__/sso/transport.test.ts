import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ApiError, customFetch } from 'panel/api/customFetch';
import { setRequestTransport } from 'panel/api/transport';
import { rememberedTransport } from 'panel/features/sso/api/transport';
import { renewSession } from 'panel/features/sso/api/sessionRenewal';

vi.mock('panel/features/sso/api/sessionRenewal', () => ({ renewSession: vi.fn() }));
const originalLocation = Object.getOwnPropertyDescriptor(window, 'location')!;
const setLocation = (href: string) => {
    const replace = vi.fn();
    Object.defineProperty(window, 'location', {
        configurable: true,
        value: { href, pathname: new URL(href).pathname, replace },
    });
    return replace;
};
beforeEach(() => {
    vi.mocked(renewSession).mockReset().mockResolvedValue(false);
    setRequestTransport(rememberedTransport);
});
afterEach(() => {
    setRequestTransport();
    Object.defineProperty(window, 'location', originalLocation);
    vi.restoreAllMocks();
});

it('retries the original request once after successful renewal', async () => {
    setLocation('https://dns.example.com/adguard/#/querylog');
    vi.mocked(renewSession).mockResolvedValue(true);
    const fetch = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(new Response('', { status: 401 }))
        .mockResolvedValueOnce(new Response('{"ok":true}', { status: 200 }));
    await expect(
        customFetch('control/settings', { method: 'POST', body: '{"enabled":true}' }),
    ).resolves.toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1]).toEqual(fetch.mock.calls[0]);
    expect(renewSession).toHaveBeenCalledOnce();
});

it('never loops when renewal succeeds but the retry is still unauthorized', async () => {
    const replace = setLocation('https://dns.example.com/adguard/');
    vi.mocked(renewSession).mockResolvedValue(true);
    const fetch = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(new Response('', { status: 401 }));
    await expect(customFetch('control/profile')).resolves.toBe(false);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(renewSession).toHaveBeenCalledOnce();
    expect(replace).toHaveBeenCalledOnce();
});

it('keeps renewal outages separate from expired credentials', async () => {
    const replace = setLocation('https://dns.example.com/adguard/');
    vi.mocked(renewSession).mockRejectedValue(new ApiError('Session renewal failed', 503));
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }));
    await expect(customFetch('control/profile')).rejects.toMatchObject({ status: 503 });
    expect(replace).not.toHaveBeenCalled();
});

it('does not try device renewal for an incorrect local password', async () => {
    setLocation('https://dns.example.com/adguard/login.html');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }));
    await expect(customFetch('control/login', { method: 'POST' })).rejects.toThrow('| 401');
    expect(renewSession).not.toHaveBeenCalled();
});
