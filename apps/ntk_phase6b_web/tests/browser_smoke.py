"""Desktop/mobile E2E smoke with an isolated fake engine; no GPU or CodeQL."""
from __future__ import annotations
import json
import sys
import tempfile
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import server
from test_app import FakeEngine


def main():
    with tempfile.TemporaryDirectory() as temp:
        w = Path(temp);(w/'batch39b2_data_runtime').mkdir()
        for split, fname in server.LOCAL_DATASET_NAMES.items():
            with (w/'batch39b2_data_runtime'/fname).open('w') as f:
                for i in range(server.EXPECTED_COUNTS[split]):
                    f.write(json.dumps({'api':'java.nio.file.Path','type':'sink' if i%2==0 else 'source','number':i})+'\n')
        eng=FakeEngine();ds=server.DatasetCatalog(w);reg=server.SessionCatalog(w/'ui')
        srv=server.create_server(eng,object(),ds,reg,port=0)
        thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
        url='http://127.0.0.1:'+str(srv.server_port)
        output=Path('/mnt/data/NTK_SAST_OnePort_v2')
        try:
            with sync_playwright() as playwright:
                browser=playwright.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
                for mode,width,height in [('desktop',1440,900),('mobile',390,844)]:
                    ctx=browser.new_context(viewport={'width':width,'height':height},device_scale_factor=1,
                                            accept_downloads=True)
                    page=ctx.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(url,wait_until='networkidle')
                    page.locator('#dataset-status').wait_for()
                    page.wait_for_timeout(300)
                    print(mode,'title',page.title(),'errors',errors,'dataset',page.locator('#dataset-status').inner_text())
                    assert 'Đã nạp 950' in page.locator('#dataset-status').inner_text(),page.locator('#dataset-status').inner_text()
                    assert '0 dự án' in page.locator('#run-status').inner_text()
                    assert not errors,errors
                    page.screenshot(path=str(output/f'preview_{mode}.png'))
                    if mode=='desktop':
                        page.get_by_role('link',name='Dữ liệu huấn luyện').click();page.wait_for_timeout(200)
                        print('excel rows',page.locator('#dataset-table tbody tr').count())
                        assert page.locator('#dataset-table tbody tr').count()==25
                        page.get_by_role('link',name='Điểm ưu tiên').click();page.wait_for_timeout(200)
                        assert 'Chưa có điểm' in page.locator('#score-overview').inner_text()
                        page.get_by_role('link',name='Quét dự án').click();page.wait_for_timeout(300)
                        page.screenshot(path=str(output/'preview_scan.png'))
                        page.get_by_role('button',name='Xem quy trình xử lý').click()
                        page.wait_for_timeout(250)
                        assert 'Chưa chạy engine' in page.locator('#job-card').inner_text()
                        page.get_by_role('link',name='Báo cáo quét').click()
                        page.screenshot(path=str(output/'preview_results_empty.png'))
                        # Fake scan integration check.
                        zip_file=w/'test.zip';zip_file.write_bytes(b'PKfake-zip-bytes-for-test-only')
                        page.get_by_role('link',name='Quét dự án').click()
                        page.locator('#project-zip').set_input_files(str(zip_file))
                        page.locator('#scan-consent').check()
                        page.once('dialog',lambda dlg:dlg.accept())
                        page.locator('#run-scan').click()
                        page.wait_for_timeout(1500)
                        page.get_by_role('link',name='Báo cáo quét').click()
                        assert '1 dự án' in page.locator('#run-status').inner_text(),page.locator('#run-status').inner_text()
                        assert '88,5' in page.locator('#inspect').inner_text(),page.locator('#inspect').inner_text()
                        page.screenshot(path=str(output/'preview_result_inspect_test_only.png'))
                        page.once('dialog',lambda dlg:dlg.accept())
                        page.get_by_role('button',name='Xóa lịch sử hiển thị').click()
                        page.wait_for_timeout(350)
                        assert '0 dự án' in page.locator('#run-status').inner_text()
                        assert reg.run_items(eng)==[]
                        print('clear confirmed, research backend not modified:',bool(eng._jobs))
                    ctx.close()
                browser.close()
        finally:
            srv.shutdown();srv.server_close();thread.join(timeout=3)

if __name__=='__main__':main()
