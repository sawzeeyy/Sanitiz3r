#!/usr/bin/env python3
# coding: utf-8
# Author: Shuaib Oladigbolu
# F007573P
# Twitter: @_sawzeeyy
# Sanitiz3r v1.0

import os
import sys
import argparse
import re
import requests
import webbrowser

# Version Compatibility
if sys.version < '3':
    import httplib
    compatibility = 0
else:
    import http.client
    compatibility = 1

# OS Compatibility : Coloring
if sys.platform.startswith('win'):
    R, B, Y, C, W = '\033[1;31m', '\033[1;37m', '\033[93m', '\033[1;30m', '\033[0m'
    try:
        import win_unicode_console, colorama
        win_unicode_console.enable()
        colorama.init()
    except:
        print('[+] Error: Coloring libraries not installed')
        R, B, Y, C, W = '', '', '', '', ''
else:
    R, B, Y, C, W = '\033[1;31m', '\033[1;37m', '\033[93m', '\033[1;30m', '\033[0m'

def header():
    print('''%s
                                                   ___        
           ()                  o        o         /   \       
           /\   __,    _  _        _|_       __     __/  ,_   
          /  \ /  |   / |/ |   |    |   |   / / _     \ /  |  
         /(__/ \_/|_/   |  |_/ |_/  |_/ |_/  /_/  \___/    |_/ v1.0
                                              /|              
         %sBy Shuaib Oladigbolu - @_sawzeeyy%s    \|%s          #F007573P %s 
        '''%(R, B, R, C, W))

def parse_error(errormsg):
    print('{}Usage: {} [Options] use -h for help'.format(Y, sys.argv[0]))
    print('{}Error: {}{}'.format(R, errormsg, W))
    sys.exit()

def parse_args():
    if sys.argv[0][0:2] == './':
        parser = argparse.ArgumentParser(description='Example: {} -v -a -d domain.com -i file.txt -o custom.html'.format(sys.argv[0]))
    else:
        parser = argparse.ArgumentParser(description='Example: python {} -v -a -d domain.com -i file.txt -o custom.html'.format(sys.argv[0]))
    parser.error = parse_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-v', '--verbose', help='Optionally log all information about the current process', required=False, action = 'store_true')
    parser.add_argument('-a', '--active', help='Optionally choose to take Sanitiz3r online to detemine the validity of subdomains', required=False, action = 'store_true')
    parser.add_argument('-d', '--domain', help='Specify a domain, a comma separated list or a file containing a list of domains to return the corresponding matching subdomains', required=True)
    parser.add_argument('-i', '--input', help='Specify an input file or a comma-separated list of the files to sanitize', required=True)
    parser.add_argument('-o', '--output', help='Optionally specify the filename to save the report', required=False)
    return parser.parse_args()

def base_url(urls_list):
    urls = []
    for url in urls_list:
        if url[0:7] == 'http://' or url[0:8] == 'https://':
            url = url.split('/')
            urls.append(url[2])
        else:
            urls.append(url)
    return urls

def get_urls(domain,files):
    url_list, urls = [], []
    for file in files:
        try:
            lines = open(file)
            line = [url.strip() for url in lines]
            line = base_url(line)
            line = [extract_url(domain,url) for url in line]
            urls += line
        except:
            print('{}Cannot find : {}{}'.format(R, file, C))

    if urls != []:
        urls = set(urls)
        for url in urls:
            if url != '':
                url_list.append(url)
        url_list.sort()
        return base_url(url_list)
    else:
        print('{}Exiting since no file(s) found!{}'.format(R, C))
        return('empty')

def extract_url(domains,line):
    urls = []
    domain = [i.split('.')[-1] for i in domains]
    sawzeeyy = '|'.join(domain)
    url_regex = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw|""" + sawzeeyy + r""")/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw|"""+ sawzeeyy + r""")\b/?(?!@)))"""
    urls_found = re.findall(url_regex, line)
    for url in urls_found:
        for domain in domains:
            if url.endswith(domain):
                urls.append(url)
    urls = ','.join(urls)
    return urls

def get_status(urls, time_out, args):
    print('{}[+] Now checking the individual subdomains{}'.format(Y, C))
    status = {}
    url_and_status = [get_url_status(url, time_out, args) for url in urls]
    url_status = [i[0] for i in url_and_status]
    unique_status = list(set(list(url_status)))
    unique_status.sort()

    for u_status in unique_status:
        temp_status = []
        for url_index in range(len(url_status)):
            if url_status[url_index] == u_status:
                temp_status.append(url_and_status[url_index][1:3])
        status[u_status] = temp_status
    return status

def get_url_status(url, timeout, arguments):
    if (arguments.verbose): print('{}[-] Checking {}{}{}'.format(C, R, url, C))
    full_http_status = get_http_status(url, timeout)
    full_https_status = get_https_status(url, timeout)
    http_url, http_status, http_title = full_http_status
    https_url, https_status, https_title = full_https_status
    url_status = min(http_status, https_status)
    status = 'Not Reachable' if url_status == 1909 else url_status
    if (arguments.verbose): print('\t{}[+] Status: {}{}'.format(Y, status, C))
    if url_status == http_status:
        if (arguments.verbose): print('\t{}[+] Title: {}{}'.format(Y, http_title, C))
        return [url_status, http_url, http_title]
    else:
        if (arguments.verbose): print('\t{}[+] Title: {}{}'.format(Y, https_title, C))
        return [url_status, https_url, https_title]


def extract_title(html_body):
    match = re.search('<title>(.*?)</title>', html_body)
    title = match.group(1) if match else 'Sorry, couldn\'t wait to check ;)'
    return title

def get_http_status(url, time_out = 10):
    try:
        if compatibility == 0:
            resp = httplib.HTTPConnection(url, timeout = time_out)
        elif compatibility == 1:
            resp = http.client.HTTPConnection(url, timeout = time_out)
        resp.request('GET', '/')
        response = resp.getresponse()
        title = extract_title(response.read().encode("utf-8"))
        return ['http://' + url, response.status, title]
    except:
        return ['http://' + url, 1909, 'Unidentified']

def get_https_status(url, time_out = 10):
    try:
        response = requests.get('https://'+url, timeout = time_out)
        title = extract_title(response.text.encode("utf-8"))
        return ['https://' + url, response.status_code, title]
    except:
        return ['https://' + url, 1909, 'Unidentified']

def generate_html_code(*args):
    mode, domain, domain_length = args[0], args[1], args[2]
    html_code, text_format = [], []
    domains = ','.join(domain)
    div_code = ''
    if mode == 'passive':
        urls = args[3]
        for url in urls:
            text_format.append(url)
            part_div_code = """
<div>
    <a href='http://www.{}' target='_blank' rel='nofollow noopener noreferrer' class='text'>http://www.{}</a> | <a href='https://www.{}' target='_blank' rel='nofollow noopener noreferrer' class='text'>https://www.{}</a>  
    <div class='container'>
      [Subdomain: '<span style='background-color:yellow'>{}</span>']
    </div>
</div>        
        """.format(url,url,url,url,url)
            div_code += part_div_code

    elif mode == 'active':
        url_and_status = args[3]
        for status in url_and_status:
            for url in url_and_status[status]:
                text_format.append(url[0].split('/')[-1])
                if status == 1909:
                    status = 'Not Reachable'
                    url[1] = 'Unidentified'
                part_div_code = """
            <div>
                <a href='{}' target='_blank' rel='nofollow noopener noreferrer' class='text'>{}</a>
                <div class='container'>
                  [Subdomain: '<span style='background-color:yellow'>{}</span>'], [Status: '<span style='background-color:yellow'>{}</span>'], [Title: '<span style='background-color:yellow'>{}</span>']
                </div>
            </div>
                    """.format(url[0], url[0], url[0].split('/')[-1], status, url[1])
                div_code += part_div_code


    style = """\
h1 {
        font-family: sans-serif;
    }
    a {
        color: #000;
    }
    .text {
        font-size: 16px;
        font-family: Helvetica, sans-serif;
        color: #323232;
        background-color: white;
    }
    .container {
        background-color: #e9e9e9;
        padding: 10px;
        margin: 10px 0;
        font-family: helvetica;
        font-size: 13px;
        border-width: 1px;
        border-style: solid;
        border-color: #8a8a8a;
        color: #323232;
        margin-bottom: 15px;
    }
    .button {
        padding: 17px 60px;
        margin: 10px 10px 10px 0;
        display: inline-block;
        background-color: #f4f4f4;
        border-radius: .25rem;
        text-decoration: none;
        -webkit-transition: .15s ease-in-out;
        transition: .15s ease-in-out;
        color: #333;
        position: relative;
    }
    .button:hover {
        background-color: #eee;
        text-decoration: none;
    }
    .github-icon {
        line-height: 0;
        position: absolute;
        top: 14px;
        left: 24px;
        opacity: 0.7;
    }
    """
    part_code = """\
<!DOCTYPE html>
<html>
<head>
  <style>
    {}
  </style>
  <title>Sanitiz3r Report - {}</title>
</head>
<body>
  <h1>Sanitiz3r Report - {} [{} Subdomain(s)]</h1>
  {}
  <a class='button' contenteditable='false' href='https://github.com/sawzeeyy/Sanitiz3r/issues/new' rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height='24' viewbox='0 0 24 24' width='24' xmlns='http://www.w3.org/2000/svg'>
  <path d='M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22' fill='none' stroke='#000' stroke-linecap='round' stroke-linejoin='round' stroke-width='2'></path></svg></span> Report an issue.</a>
</body>
</html>
    """.format(style, domains, domains, domain_length, div_code)
    html_code.append(part_code)


    return html_code, text_format

def save_html_file(code, filename):
    fh = open(os.path.dirname(os.path.abspath(__file__))+'/'+filename+'.html', 'w')
    txt = open(os.path.dirname(os.path.abspath(__file__))+'/'+filename+'.txt', 'w')
    for st in code[0]: fh.write(st)
    for text in code[1]: txt.write(text+'\n')
    fh.close()

def sanitiz3r():
    header()
    args = parse_args()
    domain = args.domain.split(',')
    filename = domain[0].split('.')[0] + '_sanitiz3r' if type(args.output) != type('F007573P') else args.output.split('.')[0] + '_sanitiz3r'
    if len(domain) == 1 and domain[0].split('.')[1] == 'txt':
        try:
            domain = open(domain[0]).readlines()
        except:
            print('{}Cannot find : {}{}'.format(R, domain[0], C))
            sys.exit()
    domain = [i.strip() for i in domain]
    file = args.input.split(',')
    urls = get_urls(domain,file)
    mode = 'active' if args.active else 'passive'

    if urls == 'empty':
        sys.exit()
    else:
        print('{}[+] {} URLs / Subdomains Sanitiz3d{}'.format(Y, len(urls), C))

    if mode == 'passive':
        html = generate_html_code(mode, domain, len(urls), urls)
        save_html_file(html, filename)

    elif mode == 'active':
        status = get_status(urls, 10, args)
        html = generate_html_code(mode, domain, len(urls), status)
        save_html_file(html, filename)
    print('{}[+] HTML Report Successfully Generated{}'.format(Y, C))
    print('{}[+] File saved as {}{}/{}.html{}'.format(Y, R, os.path.dirname(os.path.abspath(__file__)), filename, C))
    print('{}[+] Sanitiz3r Operation Completed!{}'.format(Y, W))
    try:
        webbrowser.open_new_tab('file:///' + os.path.dirname(os.path.abspath(__file__)) + '/' + filename + '.html')
    except:
        webbrowser.open_new_tab(filename + '.html')
if __name__ == '__main__': sanitiz3r()