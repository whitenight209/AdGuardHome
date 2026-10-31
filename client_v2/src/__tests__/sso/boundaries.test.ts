import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8');

describe('SSO extension boundaries for upstream sync', () => {
    it('keeps fork endpoints and schemas out of the main API specification', () => {
        const core = read('../openapi/openapi.yaml');
        expect(core).not.toContain('/sso/');
        expect(core).not.toContain('/auth/config');
        expect(core).not.toContain('SSODevice');
        expect(core).not.toContain('AuthConfig');
    });

    it('generates a dedicated client from the extension specification', () => {
        const config = read('orval.sso.config.ts');
        expect(config).toContain('../openapi/sso.yaml');
        expect(config).toContain('./src/features/sso/api/generated.ts');
        expect(read('src/features/sso/api/generated.ts')).toContain('refreshSSO');
        expect(read('src/api/generated.ts')).not.toContain('refreshSSO');
    });

    it('keeps the shared request parser independent of SSO policies', () => {
        const core = read('src/api/customFetch.ts');
        expect(core).not.toContain('/sso/');
        expect(core).not.toContain('renewSession');
        expect(core).not.toContain('remembered');
        expect(read('src/api/transport.ts')).not.toContain('features/sso');
    });

    it('retains an ordinary native transport when the extension is not installed', async () => {
        const { setRequestTransport, sendRequest } = await import('panel/api/transport');
        const { vi } = await import('vitest');
        const response = new Response('', { status: 401 });
        const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response);
        try {
            setRequestTransport();
            await expect(sendRequest('control/profile', { method: 'GET' })).resolves.toBe(response);
            expect(fetch).toHaveBeenCalledOnce();
        } finally {
            fetch.mockRestore();
            setRequestTransport();
        }
    });
});
