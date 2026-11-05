import { readFileSync } from 'node:fs';
const css = readFileSync('src/style.css', 'utf8');
import { expect, test } from 'vitest';
const luminance = (hex: string) => { const c = hex.match(/\w\w/g)!.map(x => parseInt(x, 16) / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4); return c[0] * .2126 + c[1] * .7152 + c[2] * .0722; };
test.each([['18283c', 'f4f7fa'], ['174da6', 'ffffff'], ['526379', 'ffffff'], ['8b2525', 'fff0ed'], ['294463', 'eaf0f8'], ['34516e', 'ffffff']])('text palette #%s on #%s meets WCAG AA', (a, b) => {
    expect(css.toLowerCase()).toContain('#' + a);
    const x = luminance(a), y = luminance(b);
    expect((Math.max(x, y) + .05) / (Math.min(x, y) + .05)).toBeGreaterThanOrEqual(4.5);
});
test('responsive CSS constrains tracks, wraps content, provides 44px targets and reduced motion', () => {
    expect(css).toContain('minmax(0,1fr)');
    expect(css).toContain('max-width:100%');
    expect(css).toContain('@media(max-width:700px)');
    expect(css).toContain('overflow-wrap:anywhere');
    expect(css).toContain('min-height:44px');
    expect(css).toContain('prefers-reduced-motion:reduce');
    expect(css).not.toMatch(/@import|https?:\/\//);
});
