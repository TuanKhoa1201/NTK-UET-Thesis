from __future__ import annotations
import math

def ratio(a,b): return a/b if b else None

def detection(rows, labels, selector):
    c=dict(tp=0,fp=0,fn=0,tn=0)
    for r in rows:
        y=labels[r['unit_id']]['truth']; pred=bool(r[selector])
        if y=='POSITIVE': c['tp' if pred else 'fn']+=1
        elif y=='NEGATIVE': c['fp' if pred else 'tn']+=1
        else: raise ValueError('holdout labels must be binary')
    tp,fp,fn,tn=(c[k] for k in ('tp','fp','fn','tn'))
    return {**c,'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),'f1':ratio(2*tp,2*tp+fp+fn),
            'specificity':ratio(tn,tn+fp),'positive_support':tp+fn,'negative_support':tn+fp}

def ranking(rows, labels, ks=(1,3,5,10)):
    ordered=sorted((r for r in rows if r['any_reported_alert']),key=lambda r:(-r['score'],r['unit_id']))
    gains=[int(labels[r['unit_id']]['truth']=='POSITIVE') for r in ordered]
    total=sum(labels[r['unit_id']]['truth']=='POSITIVE' for r in rows)
    groups=[]; expected=[]; off=0; before=0; exp_ap=0.0
    while off<len(ordered):
        end=off+1
        while end<len(ordered) and ordered[end]['score']==ordered[off]['score']:end+=1
        n=end-off;m=sum(gains[off:end]);p=m/n
        groups.append({'offset':off,'size':n,'positives':m,'score':ordered[off]['score']}); expected.extend([p]*n)
        for j in range(1,n+1):
            second=(j-1)*m*(m-1)/(n*(n-1)) if n>1 else 0.0
            exp_ap+=((before+1)*p+second)/(off+j)
        before+=m;off=end
    seen=0;apsum=0.0
    for i,g in enumerate(gains,1):
        seen+=g
        if g:apsum+=seen/i
    top={}
    for k in ks:
        if k>len(ordered):
            top[str(k)]={'status':'INSUFFICIENT_RETRIEVED_K','retrieved':len(ordered),'metrics':None};continue
        hits=sum(gains[:k]);eh=sum(expected[:k]);lo=hi=0
        for g in groups:
            take=max(0,min(g['size'],k-g['offset']))
            if not take:continue
            n,m=g['size'],g['positives'];lo+=max(0,take-(n-m));hi+=min(take,m)
        dcg=sum(v/math.log2(i+2) for i,v in enumerate(gains[:k])); edcg=sum(v/math.log2(i+2) for i,v in enumerate(expected[:k]))
        ideal=sum(1/math.log2(i+2) for i in range(min(k,total)))
        top[str(k)]={'status':'COMPUTED','precision':hits/k,'recall':ratio(hits,total),'ndcg_binary':ratio(dcg,ideal),
            'tie_expected_precision':eh/k,'tie_expected_recall':ratio(eh,total),'tie_expected_ndcg_binary':ratio(edcg,ideal),
            'within_tie_precision_min':lo/k,'within_tie_precision_max':hi/k}
    return {'status':'COMPUTED','universe':len(rows),'retrieved':len(ordered),'positive_support':total,
        'positive_not_retrieved':total-sum(gains),'ap_single_list_not_map':ratio(apsum,total),
        'tie_expected_ap':ratio(exp_ap,total),'tie_groups_with_multiple_units':sum(g['size']>1 for g in groups),'top_k':top}
