"""Render the production CSS in Chromium and test the frozen dataset corner.

No network, GPU, CodeQL or application backend. Chromium localhost routing may be
restricted in isolated CI, so this test renders an actual table using the CSS file.
Run: python tests/test_dataset_sticky.py
"""
from __future__ import annotations
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
CSS=(ROOT/'web/style.css').read_text(encoding='utf-8')


def close(a,b,epsilon=1.1):return abs(a-b)<epsilon


def main():
    headings=''.join(f'<th>Trường dữ liệu {i}</th>' for i in range(1,9))
    rows=''.join(
        '<tr><td class="row-num">'+str(i)+'</td>'+''.join(
            f'<td class="dataset-cell">Dòng {i} - cột {j} - dữ liệu mẫu dài</td>'
            for j in range(1,9))+'</tr>' for i in range(1,31))
    markup=f'''<!doctype html><html><head><meta charset="utf-8">
        <style>{CSS}\n.test-scroll{{width:700px;height:285px;margin:40px;}}</style></head>
        <body><div class="sheet-scroll test-scroll"><table id="dataset-table" class="excel">
        <thead><tr><th class="row-num">#</th>{headings}</tr></thead>
        <tbody>{rows}</tbody></table></div></body></html>'''
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
        try:
            page=browser.new_page(viewport={'width':1050,'height':760})
            page.set_content(markup)
            scroll=page.locator('.sheet-scroll')
            th=page.locator('#dataset-table thead th.row-num')
            first=page.locator('#dataset-table tbody tr:first-child td.row-num')
            assert th.inner_text()=='#'
            assert scroll.evaluate('(n)=>n.scrollHeight>n.clientHeight'), 'No vertical scroll'
            assert scroll.evaluate('(n)=>n.scrollWidth>n.clientWidth'), 'No horizontal scroll'
            scroll.evaluate('(n)=>{n.scrollTop=160;n.scrollLeft=190;}')
            page.wait_for_timeout(120)
            sb=scroll.bounding_box();hb=th.bounding_box();rb=first.bounding_box()
            assert close(hb['y'],sb['y']), ('header top moved',hb,sb)
            assert close(hb['x'],sb['x']), ('header left moved',hb,sb)
            assert rb['y']<hb['y']+hb['height'], ('body numbers did not scroll',rb,hb)
            assert th.evaluate('(n)=>getComputedStyle(n).zIndex')=='5'
            assert first.evaluate('(n)=>getComputedStyle(n).zIndex')=='2'
            print('STICKY_CORNER_PASS: corner # stays top-left and row numbers scroll with data')
            page.screenshot(path='/mnt/data/ntk_dataset_sticky_preview.png')
        finally:
            browser.close()

if __name__=='__main__':main()
