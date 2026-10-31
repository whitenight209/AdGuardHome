import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, customFetch } from 'panel/api/customFetch';
import { renewSession } from 'panel/api/sessionRenewal';

vi.mock('panel/api/sessionRenewal', () => ({ renewSession: vi.fn() }));
beforeEach(() => {
    vi.mocked(renewSession).mockReset().mockResolvedValue(false);
});

const originalLocation = Object.getOwnPropertyDescriptor(window, 'location')!;

afterEach(() => {
    Object.defineProperty(window, 'location', originalLocation);
    vi.restoreAllMocks();
});

const setLocation = (href: string) => {
    const url = new URL(href);
    const replace = vi.fn();
    Object.defineProperty(window, 'location', {
        configurable: true,
        value: { href, pathname: url.pathname, replace },
    });
    return replace;
};

describe('expired authentication', () => {
    it.each([401, 403])('returns to the prefixed login page on HTTP %i', async (status) => {
        const replace = setLocation('https://dns.example.com/adguard/#/querylog?search=private');
        vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status }));

        await expect(customFetch('control/status')).resolves.toBe(false);

        expect(replace).toHaveBeenCalledWith('https://dns.example.com/adguard/login.html');
    });

    it.each(['login.html', 'install.html', 'forgot_password.html'])(
        'does not redirect a failed request from the prefixed %s page',
        async (entry) => {
            const replace = setLocation(`https://dns.example.com/adguard/${entry}`);
            vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }));

            await expect(customFetch('control/login')).rejects.toThrow('| 401');

            expect(replace).not.toHaveBeenCalled();
        },
    );

    it('allows background checks to handle authentication failures without redirecting', async () => {
        const replace = setLocation('https://dns.example.com/adguard/');
        const fetch = vi
            .spyOn(globalThis, 'fetch')
            .mockResolvedValue(new Response('', { status: 401 }));

        await expect(customFetch('control/status', { skipAuthRedirect: true })).rejects.toThrow(
            '| 401',
        );

        expect(replace).not.toHaveBeenCalled();
        expect(fetch.mock.calls[0][1]).not.toHaveProperty('skipAuthRedirect');
    });

    it('keeps network failures separate from expired sessions', async () => {
        const replace = setLocation('https://dns.example.com/adguard/');
        vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));

        await expect(customFetch('control/status')).rejects.toThrow('Failed to fetch');

        expect(replace).not.toHaveBeenCalled();
    });
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
