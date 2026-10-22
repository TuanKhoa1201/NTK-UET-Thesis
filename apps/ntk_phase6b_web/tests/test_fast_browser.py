"""No-network Chromium smoke for Fast UI. Fake API is isolated test-only data."""
from __future__ import annotations
from pathlib import Path
import json
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
RID='ntkfast_20261021T085514Z_e86a3942'

def main():
    html=(ROOT/'web/index.html').read_text().replace('__NTK_LOCAL_CSRF__','test-csrf')
    css=(ROOT/'web/style.css').read_text()
    js=(ROOT/'web/app.js').read_text()
    # Avoid malformed literal script terminator in source.
    js=js.replace('</script>','<\\/script>')
    mock=r'''<script>
window.fetch=async function(input, init={}) {
 const path=String(input), method=(init.method||'GET').toUpperCase();
 const rid='ntkfast_20261021T085514Z_e86a3942';
 const details={mode:'FAST_E1_COMPLETED_PRIOR_CLI_OR_NEW_WEB_NOT_RESEARCH_FOUR_ARM',
  summary:{raw_opengrep_findings:2,elapsed_s:285.309,input_sha256:'a'.repeat(64)},
  comparison:{arms:{opengrep_only:{retained_opengrep:2,qualified_paths:0},
  epoch_1:{retained_opengrep:2,evidence_by_cwe:{'22':{qualified_paths:0},'78':{qualified_paths:1},'79':{qualified_paths:0},'89':{qualified_paths:0}}}}},
  native:{epoch_1:{accepted:1,abstain:1}},profile_discovery:{active_cwes:['78','89'],no_candidates_cwes:['22','79']}};
 const row={id:'opengrep:0',cwe:'78',rule_id:'test-rule',origin:'OPENGREP',
  score:{final_score:77.5,risk_level:'HIGH',ai_confidence_score:0.5},
  location:{uri:'src/Test.java',start_line:8,start_column:3},
  evidence_status:'REVIEW_REQUIRED',evidence_origin:'MODEL_DERIVED',
  model:{status:'ACCEPTED',role:'sink',reason:'TEST_ONLY'},dataflow:[],callsite:{method:'exec'}};
 let value=null;
 if(path==='/api/connect')value={connected:true,backend:{scan_enabled:true,fast_available:true,registered_runs:1},single_port:true};
 else if(path==='/api/jobs')value=[];
 else if(path==='/api/runs')value=[{run_id:rid,project:'GitHub Java (đã phân tích trước)',mode:'fast',imported_prior_cli:true,status:'COMPLETE'}];
 else if(path==='/api/runs/'+rid)value=details;
 else if(path==='/api/runs/'+rid+'/epoch_1'||path==='/api/runs/'+rid+'/opengrep_only')value={run_id:rid,arm:'epoch_1',findings:[row]};
 else if(path==='/api/dataset/info')value={train:{available:false,count:0,sha256:null},validation:{available:false,count:0,sha256:null}};
 else value={error:'MOCK_NOT_CONFIGURED '+path};
 const ok=value.error===undefined;
 return {ok,status:ok?200:404,headers:new Headers({'content-type':'application/json'}),json:async()=>value,text:async()=>JSON.stringify(value)};
};
</script>'''
    html=html.replace('<script defer src="/app.js"></script>',mock+'<script>'+js+'</script>')
    html=html.replace('</head>','<style>'+css+'</style></head>')
    with sync_playwright() as api:
        browser=api.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
        try:
            for width,height in ((1440,900),(390,844)):
                page=browser.new_page(viewport={'width':width,'height':height})
                errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.set_content(html,wait_until='domcontentloaded')
                page.wait_for_timeout(500)
                assert not errors, errors
                assert page.locator('#scan-mode').input_value()=='fast'
                assert page.locator('#run-select option').count()==1
                assert page.locator('#finding-arm option').count()==2
                assert page.locator('#finding-arm').input_value()=='epoch_1'
                assert '77,5' in page.locator('#score-overview').inner_text()
                assert 'CWE-22' in page.locator('#run-summary').inner_text()
                print('FAST_UI_CHROMIUM_PASS',width,page.locator('#run-status').inner_text())
                page.close()
        finally:browser.close()
if __name__=='__main__': main()
