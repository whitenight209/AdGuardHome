import { expect, test } from '@playwright/test';
import { login } from '../helpers/login';

test('a persistent login survives a recreated browser context and logout revokes it', async ({ page, browser }) => {
    await login(page);
    const state = await page.context().storageState();
    const cookie = state.cookies.find((entry) => entry.name === 'agh_session');
    expect(cookie).toBeDefined();
    expect(cookie!.expires).toBeGreaterThan(Date.now() / 1000);
    expect(cookie!.httpOnly).toBe(true);

    const context = await browser.newContext({ storageState: state });
    try {
        const restored = await context.newPage();
        await restored.goto(new URL('/', page.url()).href);
        await expect(restored).not.toHaveURL(/login\.html/);
        const profileUrl = new URL('control/profile', restored.url()).href;
        expect((await context.request.get(profileUrl)).status()).toBe(200);

        await restored.goto(new URL('control/logout', restored.url()).href);
        await expect(restored).toHaveURL(/login\.html/);
        // Even the original browser's copy of the token must be revoked.
        expect((await page.context().request.get(profileUrl)).status()).toBe(401);
    } finally {
        await context.close();
    }
});

test('returning to an app with an expired session promptly opens login', async ({ page }) => {
    await login(page);
    await expect(page.locator('#sign_out').first()).toBeAttached();
    await page.context().clearCookies();
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await expect(page).toHaveURL(/login\.html/, { timeout: 5000 });
});
