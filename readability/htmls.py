from cleaners import normalize_spaces, clean_attributes
from encoding import get_encoding
from lxml.html import tostring
from lxml.etree import tounicode
import logging
import lxml.html
import re

logging.getLogger().setLevel(logging.DEBUG)

utf8_parser = lxml.html.HTMLParser(encoding='utf-8')

def build_doc(page):
    if isinstance(page, unicode):
        page_unicode = page
    else:
        enc = get_encoding(page)
        page_unicode = page.decode(enc, 'replace')
    doc = lxml.html.document_fromstring(page_unicode.encode('utf-8', 'replace'), parser=utf8_parser)
    return doc

def js_re(src, pattern, flags, repl):
    return re.compile(pattern, flags).sub(src, repl.replace('$', '\\'))


def normalize_entities(cur_title):
    entities = {
        u'\u2014':'-',
        u'\u2013':'-',
        u'&mdash;': '-',
        u'&ndash;': '-',
        u'\u00A0': ' ',
        u'\u00AB': '"',
        u'\u00BB': '"',
        u'&quot;': '"',
    }
    for c, r in entities.iteritems():
        if c in cur_title:
            cur_title = cur_title.replace(c, r)

    return cur_title

def norm_title(title):
    return normalize_entities(normalize_spaces(title))

def get_title(doc):
    title = doc.find('.//title')
    if title is None or not title.text:
        return '[no-title]'

    return norm_title(title.text)

def add_match(collection, text, orig):
    text = norm_title(text)
    if len(text) >= 5:
        if text.replace('"', '') in orig.replace('"', ''):
            collection.add(text)

def shorten_title(doc):
    title = doc.find('.//title')
    if title is None or title.text is None or len(title.text) == 0:
        return ''

    title = orig = norm_title(title.text)
    candidates = set() 

    for item in ['.//h1', './/h2', './/h3']:
        for e in list(doc.iterfind(item)):
            text = e.text or e.text_content()
            add_match(candidates, text, orig)
    for item in ['#title', '#head', '#heading', '.pageTitle', '.news_title', '.title', '.head', '.heading', '.contentheading', '.small_header_red']:
        for e in doc.cssselect(item):
            text = e.text or e.text_content()
            add_match(candidates, text, orig)
    if candidates:
        title = sorted(candidates, key=len)[-1]
    #else:
    for delimiter in ['|', '-', ' :: ', ' / ', '_', " "]:
        if delimiter in title:
            parts = orig.split(delimiter)
            title = parts[0]
            #if len(parts[0].split()) >= 4:
            #    title = parts[0]
            #    break
            #elif len(parts[-1].split()) >= 4:
            #    title = parts[-1]
            #    break
    else:
        if ': ' in title:
            parts = orig.split(': ')
            if len(parts[-1].split()) >= 4:
                title = parts[-1]
            else:
                title = orig.split(': ', 1)[1]

    if not 5 < len(title) < 150:
        return orig
    return title

def get_body(doc):
    [ elem.drop_tree() for elem in doc.xpath('.//script | .//link | .//style') ]
    raw_html = unicode(tostring(doc.body or doc))
    cleaned = clean_attributes(raw_html)
    try:
        #BeautifulSoup(cleaned) #FIXME do we really need to try loading it?
        return cleaned
    except Exception: #FIXME find the equivalent lxml error
        logging.error("cleansing broke html content: %s\n---------\n%s" % (raw_html, cleaned))
        return raw_html







def remove_ctrl_char(origin_str):
    #ctr_chars = [u'\x%02d' % i for i in range(0, 32)]
    ctr_chars = [u'\u0000', u'\u0001', u'\u0002', u'\u0003', u'\u0004', u'\u0005', u'\u0006', u'\u0007', u'\u0008', u'\u0009',
                 u'\u000a', u'\u000b', u'\u000c', u'\u000d', u'\u000e', u'\u000f', u'\u0010', u'\u0011', u'\u0012', u'\u0013',
                 u'\u0014', u'\u0015', u'\u0016', u'\u0017', u'\u0018', u'\u0019', u'\u001a', u'\u001b', u'\u001c', u'\u001d',
                 u'\u001e', u'\u001f']
    if not isinstance(origin_str, unicode):
        origin_str = unicode(origin_str)

    regex = re.compile(u'|'.join(ctr_chars))
    return regex.subn(u'', origin_str)[0]


def merge_space(origin_str):
    if not isinstance(origin_str, unicode):
        origin_str = unicode(origin_str)
    regex = re.compile(u"(\s)+", re.UNICODE)
    return regex.subn(u'\\1', origin_str)[0]
