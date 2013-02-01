#coding=utf-8

from readability.readability import Document

def main():
    html = open('./samples/21853124_0.shtml').read()
    doc = Document(html)
    doc.transform()
    doc.get_publish_date()
    doc.short_title()
    doc.text_content()

if __name__ == '__main__':
    from timeit import Timer
    t = Timer("main()", "from __main__ import main")
    print t.repeat(3, number=100)

