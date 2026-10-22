"""Bounded local-only dataset parsing and Excel export."""
from __future__ import annotations
import csv
import html
import io
import json
import re
import zipfile
from xml.etree import ElementTree as ET

MAX_ROWS=3000
MAX_COLS=64
XMLNS='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
REL_NS='http://schemas.openxmlformats.org/officeDocument/2006/relationships'

def limited_text(v, size=32767):
    if v is None: return ''
    if not isinstance(v, str):
        v = json.dumps(v, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if len(v)>size and size==32767:
        raise ValueError('Một ô dữ liệu dài hơn 32767 ký tự, không thể xuất XLSX mà không mất dữ liệu.')
    return ''.join(ch for ch in v[:size] if ch >= ' ' or ch in '\n\t')


def normalize_rows(header, values):
    names=[]
    for i, name in enumerate(header[:MAX_COLS]):
        n=limited_text(name,100).strip() or ('Col_'+str(i+1))
        if n in names: n=n+'_'+str(i+1)
        names.append(n)
    if not names or not any(x for x in names):
        raise ValueError('Không tìm thấy cột dữ liệu hợp lệ.')
    result=[]
    for row in values:
        if len(result)>=MAX_ROWS: raise ValueError('Dataset vượt giới hạn 3000 bản ghi/lần.')
        result.append([limited_text(row[i]) if i<len(row) else '' for i in range(len(names))])
    return {'columns': names, 'rows': result, 'count': len(result),
            'privacy': 'LOCAL_MEMORY_ONLY_NO_STORAGE',
            'note': 'Dữ liệu được đọc trong RAM của máy cục bộ, không huấn luyện hoặc gửi lên cloud.'}


def parse_jsonl(blob):
    rows=[];keys=[]
    for n,line in enumerate(blob.decode('utf-8-sig').splitlines(),1):
        if not line.strip():continue
        try: item=json.loads(line)
        except (json.JSONDecodeError,ValueError) as e:raise ValueError('JSONL không hợp lệ tại dòng '+str(n)) from e
        if not isinstance(item,dict):raise ValueError('Mỗi dòng JSONL phải là object.')
        for k in item:
            if k not in keys:
                keys.append(k)
                if len(keys)>MAX_COLS:raise ValueError('Vượt giới hạn 64 cột.')
        rows.append(item)
        if len(rows)>MAX_ROWS:raise ValueError('Vượt giới hạn 3000 bản ghi.')
    if not rows:raise ValueError('Tệp JSONL không có bản ghi.')
    return normalize_rows(keys,([r.get(k) for k in keys] for r in rows))


def parse_csv(blob, delimiter=None):
    txt=blob.decode('utf-8-sig')
    if not delimiter:
        try: delimiter=csv.Sniffer().sniff(txt[:4096],delimiters=',;\t').delimiter
        except csv.Error: delimiter=','
    table=csv.reader(io.StringIO(txt),delimiter=delimiter)
    header=next(table,None)
    if not header:raise ValueError('Tệp CSV trống.')
    return normalize_rows(header,table)


def col_index(ref):
    col=re.match(r'^([A-Z]{1,3})[0-9]+$',ref or '')
    if not col:return None
    index=0
    for char in col.group(1):index=index*26+ord(char)-64
    return index-1


def parse_xlsx(blob):
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            info=z.infolist()
            if len(info)>250 or sum(i.file_size for i in info)>32*1024*1024:
                raise ValueError('Workbook quá lớn.')
            names={p.filename for p in info}
            if len(names)!=len(info) or 'xl/worksheets/sheet1.xml' not in names:
                raise ValueError('XLSX phải có sheet đầu tiên (sheet1).')
            for item in info:
                if '..' in item.filename.split('/') or item.filename.startswith('/'):
                    raise ValueError('Đường dẫn không an toàn trong XLSX.')
            def safe_xml(name):
                raw=z.read(name)
                if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
                    raise ValueError('XML trong XLSX không hợp lệ.')
                return ET.fromstring(raw)
            strings=[]
            if 'xl/sharedStrings.xml' in names:
                ss=safe_xml('xl/sharedStrings.xml')
                for si in ss.findall('{%s}si'%XMLNS):
                    strings.append(''.join((t.text or '') for t in si.iter('{%s}t'%XMLNS)))
            root=safe_xml('xl/worksheets/sheet1.xml')
            data=[]
            for rr in root.findall('.//{%s}sheetData/{%s}row'%(XMLNS,XMLNS)):
                mapping={}
                for cell in rr.findall('{%s}c'%XMLNS):
                    idx=col_index(cell.attrib.get('r',''))
                    if idx is None or idx>=MAX_COLS:continue
                    typ=cell.attrib.get('t','')
                    if typ=='inlineStr':
                        value=''.join((t.text or '') for t in cell.iter('{%s}t'%XMLNS))
                    else:
                        v=cell.find('{%s}v'%XMLNS)
                        value=v.text if v is not None and v.text is not None else ''
                        if typ=='s':
                            try:value=strings[int(value)]
                            except (ValueError,IndexError):value=''
                    mapping[idx]=value
                if mapping:
                    width=min(MAX_COLS,max(mapping)+1)
                    data.append([mapping.get(i,'') for i in range(width)])
                if len(data)>MAX_ROWS+1:raise ValueError('Vượt giới hạn 3000 bản ghi.')
            if not data:raise ValueError('Sheet đầu tiên không chứa dữ liệu.')
            return normalize_rows(data[0],data[1:])
    except (zipfile.BadZipFile,KeyError,ET.ParseError) as e:
        raise ValueError('Không đọc được XLSX. Hãy chọn workbook chuẩn hoặc dùng CSV/JSONL.') from e


def create_xlsx(columns, rows, sheetname='Dataset'):
    """Tiny dependency-free XLSX writer, serializing ALL cells as literal strings."""
    if not isinstance(columns,list) or not isinstance(rows,list) or len(columns)>MAX_COLS or len(rows)>MAX_ROWS or not columns:
        raise ValueError('Dữ liệu export không hợp lệ hoặc vượt giới hạn.')
    for r in rows:
        if not isinstance(r,list) or len(r)>MAX_COLS:raise ValueError('Hàng export không hợp lệ.')
    nsp='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    ET.register_namespace('', nsp)
    ws=ET.Element('{%s}worksheet'%nsp)
    sheet_data=ET.SubElement(ws,'{%s}sheetData'%nsp)
    for i,vals in enumerate([columns]+rows,1):
        rr=ET.SubElement(sheet_data,'{%s}row'%nsp,{'r':str(i)})
        for j,val in enumerate(vals,1):
            col=''; k=j
            while k: k,rem=divmod(k-1,26);col=chr(65+rem)+col
            c=ET.SubElement(rr,'{%s}c'%nsp,{'r':col+str(i),'t':'inlineStr'})
            ins=ET.SubElement(c,'{%s}is'%nsp)
            ET.SubElement(ins,'{%s}t'%nsp).text=limited_text(val,32767)
    content=io.BytesIO()
    with zipfile.ZipFile(content,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','''<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>''')
        z.writestr('_rels/.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>''')
        safe_sheet=re.sub(r'[\\/*?:\[\]]','_',sheetname)[:31] or 'Dataset'
        z.writestr('xl/workbook.xml',f'''<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="{nsp}" xmlns:r="{REL_NS}"><sheets><sheet name="{html.escape(safe_sheet,quote=True)}" sheetId="1" r:id="rId1"/></sheets></workbook>''')
        z.writestr('xl/_rels/workbook.xml.rels','''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>''')
        z.writestr('xl/worksheets/sheet1.xml',ET.tostring(ws,encoding='utf-8',xml_declaration=True))
    return content.getvalue()

