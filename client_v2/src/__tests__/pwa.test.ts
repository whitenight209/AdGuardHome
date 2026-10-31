import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const publicDir = resolve(process.cwd(), 'public');
const manifestPath = 'assets/manifest.json';
const manifest = JSON.parse(readFileSync(resolve(publicDir, manifestPath), 'utf8'));

describe('PWA installation', () => {
    it.each(['index', 'login', 'install', 'forgot_password'])(
        'advertises the same app from the %s entry point',
        (entry) => {
            const html = readFileSync(resolve(publicDir, `${entry}.html`), 'utf8');

            expect(html).toContain(`<link rel="manifest" href="${manifestPath}" />`);
            expect(html).toContain('name="apple-mobile-web-app-capable" content="yes"');
            expect(html).toContain(`name="theme-color" content="${manifest.theme_color}"`);
        },
    );

    it.each(['/', '/adguard/', '/nested/dns/'])(
        'keeps app identity, launch and navigation scope within %s',
        (prefix) => {
            const appUrl = new URL(prefix, 'https://example.test');
            const manifestUrl = new URL(manifestPath, appUrl);

            for (const field of ['id', 'start_url', 'scope']) {
                expect(new URL(manifest[field], manifestUrl).href).toBe(appUrl.href);
            }

            expect(manifest.display).toBe('standalone');
            expect(manifest.name).toBeTruthy();
        },
    );

    it.each([192, 512])('provides a valid %i pixel PNG install icon', (size) => {
        const icon = manifest.icons.find((entry: { sizes: string }) => entry.sizes === `${size}x${size}`);

        expect(icon).toBeDefined();
        expect(icon.type).toBe('image/png');

        const png = readFileSync(resolve(publicDir, 'assets', icon.src));

        expect(png.subarray(0, 8).toString('hex')).toBe('89504e470d0a1a0a');
        expect(png.readUInt32BE(16)).toBe(size);
        expect(png.readUInt32BE(20)).toBe(size);
    });
});
