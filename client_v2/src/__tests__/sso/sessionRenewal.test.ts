import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renewSession } from 'panel/features/sso/api/sessionRenewal';

const originalLocation = Object.getOwnPropertyDescriptor(window, 'location')!;
const originalLocks = Object.getOwnPropertyDescriptor(navigator, 'locks');

beforeEach(() => {
    Object.defineProperty(window, 'location', {
        configurable: true,
        value: { href: 'https://dns.example.com/adguard/#/querylog?search=private' },
    });
    Object.defineProperty(navigator, 'locks', { configurable: true, value: undefined });
});

afterEach(() => {
    Object.defineProperty(window, 'location', originalLocation);
    if (originalLocks) Object.defineProperty(navigator, 'locks', originalLocks);
    else Reflect.deleteProperty(navigator, 'locks');
    vi.restoreAllMocks();
});

describe('remembered-session renewal', () => {
    it('uses the current cookie without rotating when another tab already renewed it', async () => {
        const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));
        await expect(renewSession()).resolves.toBe(true);
        expect(fetch).toHaveBeenCalledOnce();
        expect(String(fetch.mock.calls[0][0])).toBe(
            'https://dns.example.com/adguard/control/profile',
        );
    });

    it('renews through a same-origin POST and never puts credentials in JavaScript', async () => {
        const fetch = vi
            .spyOn(globalThis, 'fetch')
            .mockResolvedValueOnce(new Response('', { status: 401 }))
            .mockResolvedValueOnce(new Response(null, { status: 204 }));
        await expect(renewSession()).resolves.toBe(true);
        expect(String(fetch.mock.calls[1][0])).toBe(
            'https://dns.example.com/adguard/control/sso/refresh',
        );
        expect(fetch.mock.calls[1][1]).toEqual({
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
        });
    });

    it.each([401, 404])('requires login when the renewal endpoint returns %i', async (status) => {
        vi.spyOn(globalThis, 'fetch')
            .mockResolvedValueOnce(new Response('', { status: 401 }))
            .mockResolvedValueOnce(new Response('', { status }));
        await expect(renewSession()).resolves.toBe(false);
    });

    it.each([403, 429, 500, 503])(
        'preserves renewal failure %i instead of treating it as logout',
        async (status) => {
            vi.spyOn(globalThis, 'fetch')
                .mockResolvedValueOnce(new Response('', { status: 401 }))
                .mockResolvedValueOnce(new Response('', { status }));
            await expect(renewSession()).rejects.toMatchObject({ status });
        },
    );

    it('does not renew when the profile server is unavailable', async () => {
        const fetch = vi
            .spyOn(globalThis, 'fetch')
            .mockResolvedValue(new Response('', { status: 503 }));
        await expect(renewSession()).rejects.toMatchObject({ status: 503 });
        expect(fetch).toHaveBeenCalledOnce();
    });

    it('coalesces simultaneous unauthorized requests into one rotation', async () => {
        let resolve!: (response: Response) => void;
        const profile = new Promise<Response>((done) => {
            resolve = done;
        });
        const fetch = vi
            .spyOn(globalThis, 'fetch')
            .mockReturnValueOnce(profile)
            .mockResolvedValueOnce(new Response(null, { status: 204 }));
        const first = renewSession();
        const second = renewSession();
        expect(first).toBe(second);
        resolve(new Response('', { status: 401 }));
        await expect(Promise.all([first, second])).resolves.toEqual([true, true]);
        expect(fetch).toHaveBeenCalledTimes(2);
    });

    it('checks the shared cookie after obtaining the cross-tab lock', async () => {
        const order: string[] = [];
        const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
            order.push('profile');
            return new Response('{}');
        });
        const request = vi.fn(async (_key: string, action: () => Promise<boolean>) => {
            order.push('lock');
            return action();
        });
        Object.defineProperty(navigator, 'locks', { configurable: true, value: { request } });
        await expect(renewSession()).resolves.toBe(true);
        expect(order).toEqual(['lock', 'profile']);
        expect(request.mock.calls[0][0]).toBe(
            'agh-sso:https://dns.example.com/adguard/control/sso/refresh',
        );
        expect(fetch).toHaveBeenCalledOnce();
    });

    it('can try again after a network failure without retaining a rejected flight', async () => {
        const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new TypeError('offline'));
        await expect(renewSession()).rejects.toThrow('offline');
        fetch.mockResolvedValueOnce(new Response('{}'));
        await expect(renewSession()).resolves.toBe(true);
        expect(fetch).toHaveBeenCalledTimes(2);
    });
});
