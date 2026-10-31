import { expect, test } from '@playwright/test';

test('login exposes an installable app without authentication', async ({ page, request }) => {
    await page.goto('/login.html');

    const manifestLink = page.locator('link[rel="manifest"]');
    await expect(manifestLink).toHaveAttribute('href', 'assets/manifest.json');

    const manifestUrl = new URL((await manifestLink.getAttribute('href'))!, page.url());
    const response = await request.get(manifestUrl.href);
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toMatch(/json|manifest/);

    const manifest = await response.json();
    expect(manifest.display).toBe('standalone');
    expect(new URL(manifest.start_url, manifestUrl).pathname).toBe('/');
    expect(new URL(manifest.scope, manifestUrl).pathname).toBe('/');

    for (const icon of manifest.icons) {
        const iconUrl = new URL(icon.src, manifestUrl);
        const imageResponse = await request.get(iconUrl.href);
        expect(imageResponse.status()).toBe(200);
        expect(imageResponse.headers()['content-type']).toContain('image/png');
    }

    const session = await page.context().newCDPSession(page);
    const parsedManifest = await session.send('Page.getAppManifest');
    expect(parsedManifest.errors).toEqual([]);
});
