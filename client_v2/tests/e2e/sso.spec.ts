import { expect, test } from '@playwright/test';

test('disabled SSO keeps the real local login page usable', async ({ page, request }) => {
    const response = await request.get('/control/auth/config');
    expect(response.ok()).toBeTruthy();
    expect(await response.json()).toEqual({ local_login_enabled: true, sso_enabled: false });
    await page.goto('/login.html');
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('a[href="/control/sso/oidc/start"]')).toHaveCount(0);
});

test('configured provider appears without automatically navigating', async ({ page }) => {
    await page.route('**/control/auth/config', (route) => route.fulfill({
        json: {
            local_login_enabled: true,
            sso_enabled: true,
            sso_display_name: 'Google',
            sso_start_url: '/control/sso/oidc/start',
        },
    }));
    await page.goto('/login.html');
    await expect(page.getByRole('link', { name: 'Sign in with Google' })).toBeVisible();
    await expect(page.locator('#username')).toHaveCount(0);
    await expect(page.locator('#password, #sign_in, a[href*="forgot_password"]')).toHaveCount(0);
    await expect(page).toHaveURL(/\/login\.html$/);
});

test('callback errors are sanitized and leave local recovery available', async ({ page }) => {
    await page.goto('/login.html?sso_error=untrusted-provider-description');
    await expect(page.getByRole('alert')).toContainText('SSO sign-in');
    await expect(page.locator('body')).not.toContainText('untrusted-provider-description');
    await expect(page.locator('#username')).toBeVisible();
});

test('SSO login presentation works under a stripping reverse proxy', async ({ page }) => {
    const { createServer, request: proxyRequest } = await import('node:http');
    const server = createServer((request, response) => {
        if (!request.url?.startsWith('/vault/')) {
            response.writeHead(404).end();
            return;
        }
        const upstream = proxyRequest({
            hostname: '127.0.0.1',
            port: 3000,
            path: request.url.slice('/vault'.length),
            method: request.method,
            headers: request.headers,
        }, (result) => {
            response.writeHead(result.statusCode ?? 502, result.headers);
            result.pipe(response);
        });
        upstream.on('error', () => response.writeHead(502).end());
        request.pipe(upstream);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
        const address = server.address();
        if (!address || typeof address === 'string') throw new Error('Missing proxy port');
        await page.route('**/vault/control/auth/config', (route) => route.fulfill({
            json: {
                local_login_enabled: true,
                sso_enabled: true,
                sso_display_name: 'Google',
                sso_start_url: '/vault/control/sso/oidc/start',
            },
        }));
        await page.goto(`http://127.0.0.1:${address.port}/vault/login.html`);
        const link = page.getByRole('link', { name: 'Sign in with Google' });
        await expect(link).toBeVisible();
        await expect(link).toHaveAttribute('href', '/vault/control/sso/oidc/start');
        await expect(page.locator('#username')).toHaveCount(0);
    } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
});

for (const theme of ['light', 'dark']) {
    for (const width of [390, 1280]) {
        test(`SSO button supports ${theme} theme at ${width}px`, async ({ page }) => {
            await page.setViewportSize({ width, height: 800 });
            await page.route('**/control/auth/config', (route) => route.fulfill({ json: {
                local_login_enabled: true, sso_enabled: true,
                sso_display_name: 'Google', sso_start_url: '/control/sso/oidc/start',
            } }));
            await page.goto('/login.html');
            await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
            const link = page.getByRole('link', { name: 'Sign in with Google' });
            await expect(link).toBeVisible();
            await expect(link.locator('svg')).toHaveAttribute('aria-hidden', 'true');
            await link.focus();
            await expect(link).toBeFocused();
            expect(await link.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe('solid');
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
            await page.screenshot({ path: `/tmp/adguard-sso-${theme}-${width}.png` });
        });
    }
}
