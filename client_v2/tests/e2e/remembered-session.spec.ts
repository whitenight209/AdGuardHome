import { expect, test, type Page } from '@playwright/test';
import { login } from '../helpers/login';

// The backend still authenticates every retried request. Only the renewal
// response is simulated; signed OIDC issuance/rotation is covered in Go tests.
const prepareRememberedBrowser = async (page: Page) => {
    await login(page);
    await expect(page.locator('#sign_out').first()).toBeAttached();
    await page.waitForLoadState('networkidle');
    const cookies = await page.context().cookies();
    const access = cookies.find((cookie) => cookie.name === 'agh_session')!;
    await page.context().addCookies([{
        name: 'agh_sso_refresh', value: 'fixture-refresh',
        domain: access.domain, path: '/', httpOnly: true,
        expires: Math.floor(Date.now() / 1000) + 180 * 24 * 60 * 60,
        sameSite: 'Lax', secure: false,
    }]);
    await page.context().clearCookies({ name: 'agh_session' });
    return access;
};

test('a remembered app restores its short session when reopened', async ({ page }) => {
    const access = await prepareRememberedBrowser(page);
    let rotations = 0;
    await page.route('**/control/auth/config', (route) => route.fulfill({ json: {
        local_login_enabled: true, sso_enabled: true,
        sso_display_name: 'Google', sso_start_url: '/control/sso/oidc/start',
    } }));
    await page.route('**/control/sso/refresh', async (route) => {
        rotations++;
        expect(route.request().method()).toBe('POST');
        await route.fulfill({ status: 204, headers: {
            'set-cookie': `agh_session=${access.value}; Path=/; HttpOnly; SameSite=Lax`,
        } });
    });
    await page.goto('/');
    await expect(page.locator('#sign_out').first()).toBeAttached();
    await expect(page).not.toHaveURL(/login\.html/);
    expect(rotations).toBe(1);
});

test('simultaneous app-resume checks share one cookie rotation', async ({ page }) => {
    const access = await prepareRememberedBrowser(page);
    let rotations = 0;
    await page.route('**/control/sso/refresh', async (route) => {
        rotations++;
        await route.fulfill({ status: 204, headers: {
            'set-cookie': `agh_session=${access.value}; Path=/; HttpOnly; SameSite=Lax`,
        } });
    });
    await page.evaluate(() => {
        document.dispatchEvent(new Event('visibilitychange'));
        document.dispatchEvent(new Event('visibilitychange'));
    });
    await expect.poll(() => rotations).toBe(1);
    await expect(page).not.toHaveURL(/login\.html/);
    await expect.poll(async () =>
        (await page.context().request.get(new URL('control/profile', page.url()).href)).status(),
    ).toBe(200);
});

test('a revoked remembered cookie offers Google login without a redirect loop', async ({ page }) => {
    await prepareRememberedBrowser(page);
    let rotations = 0;
    await page.route('**/control/auth/config', (route) => route.fulfill({ json: {
        local_login_enabled: true, sso_enabled: true,
        sso_display_name: 'Google', sso_start_url: '/control/sso/oidc/start',
    } }));
    await page.route('**/control/sso/refresh', (route) => {
        rotations++;
        return route.fulfill({ status: 401 });
    });
    await page.goto('/');
    const choice = page.locator('#sso-remember-device');
    await expect(choice).toBeVisible();
    await choice.focus();
    await choice.press('Space');
    await expect(choice).toBeChecked();
    await expect(page.locator('a[href="/control/sso/oidc/start?remember=1"]')).toBeVisible();
    await expect.poll(() => rotations).toBe(1);
    await expect(page).toHaveURL(/login\.html/);
});

test('renewal outages preserve the long cookie and keep the app open', async ({ page }) => {
    await prepareRememberedBrowser(page);
    let rotations = 0;
    await page.route('**/control/sso/refresh', (route) => {
        rotations++;
        return route.fulfill({ status: 503 });
    });
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await expect.poll(() => rotations).toBeGreaterThan(0);
    await expect(page).not.toHaveURL(/login\.html/);
    const cookies = await page.context().cookies();
    expect(cookies.find((cookie) => cookie.name === 'agh_sso_refresh')?.value).toBe('fixture-refresh');
});
