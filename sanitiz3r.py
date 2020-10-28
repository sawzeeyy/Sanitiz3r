#!/usr/bin/env python3
# coding: utf-8
# Author: Shuaib Oladigbolu
# F007573P
# Twitter: @_sawzeeyy
# Sanitiz3r v1.1

import os
import sys
import argparse
import re
import requests
import webbrowser
import http.client
from concurrent.futures import ThreadPoolExecutor

if sys.version < '3':
    print('[+] Please use python3')
    sys.exit()

# OS Compatibility : Coloring
R, B, Y, C, W = [
    '\033[1;31m', '\033[1;37m', '\033[93m', '\033[1;30m', '\033[0m']
if sys.platform.startswith('win'):
    try:
        import win_unicode_console
        import colorama
        win_unicode_console.enable()
        colorama.init()
    except ImportError:
        print('[+] Error: Coloring libraries not installed')
        R, B, Y, C, W = '', '', '', '', ''


def header():
    print('''%s
                                           ___
   ()                  o        o         /   \\
   /\\   __,    _  _        _|_       __     __/  ,_
  /  \\ /  |   / |/ |   |    |   |   / / _     \\ /  |
 /(__/ \\_/|_/   |  |_/ |_/  |_/ |_/  /_/  \\___/    |_/ v1.1
                                      /|
 %sBy Shuaib Oladigbolu - @_sawzeeyy%s    \\|%s          #F007573P %s
    ''' % (R, B, R, C, W))


def parse_error(errormsg):
    if len(sys.argv[0]) < 7:
        print(
            '{}Usage: {} [Options] use -h for help\
            '.format(Y, sys.argv[0]))
    else:
        print(
            '{}Usage: {} [Options] use -h for help\
            '.format(Y, sys.argv[0].split('/')[-1]))

    print('{}Error: {}{}'.format(R, errormsg, W))
    sys.exit()


def parse_args():
    if sys.argv[0][0:2] == './':
        parser = argparse.ArgumentParser(
            description='Example: {} -v -a -d domain.com -i\
                 file.txt -o custom.html'.format(sys.argv[0]))
    else:
        parser = argparse.ArgumentParser(
            description='Example: python {} -v -a -d domain.com\
                 -i file.txt -o custom.html'.format(sys.argv[0]))

    parser.error = parse_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument(
        '-v', '--verbose',
        help='Optionally log all information about the current process',
        required=False,
        action='store_true'
    )
    parser.add_argument(
        '-a', '--active',
        help='Optionally choose to take Sanitiz3r online to detemine\
             the validity of subdomains',
        required=False,
        action='store_true'
    )
    parser.add_argument(
        '-d', '--domain',
        help='Specify a comma-separated list of domains, or a file\
             containing a list of domains to return the corresponding\
             matching subdomains',
        required=True
    )
    parser.add_argument(
        '-i', '--input',
        help='Specify an input file or a comma-separated list\
             of the files to sanitize',
        required=True
    )
    parser.add_argument(
        '-o', '--output',
        help='Optionally specify the filename to save the report',
        required=False
    )
    parser.add_argument(
        '-t', '--thread',
        help='Number of threads, default=10',
        default=10,
        required=False
    )
    parser.add_argument(
        '--timeout',
        help='Maximum time to request for a URL, default=10',
        default=10,
        required=False
    )
    parser.add_argument(
        '-r', '--resolved',
        help='Optionally filter resolved URLs',
        required=False,
        action='store_true'
    )
    return parser.parse_args()


def base_url(url):
    if url.startswith('http://') or url.startswith('https://'):
        return url.split('/')[2]
    return url


def get_urls(domain, files):
    urls = []
    for f in files:
        try:
            lines = open(f).readlines()
            line = [base_url(url.strip()) for url in lines]
            line = [extract_url(domain, url) for url in line]
            urls.extend(line)
        except IOError:
            print('{}Cannot find : {}{}'.format(R, f, C))

    urls = set(urls)
    if urls:
        urls = [url for url in urls if url != '']
        return urls
    else:
        print('{}Exiting since no file(s) found!{}'.format(R, C))
        sys.exit()


def extract_url(domain, url):
    for d in domain:
        if url.endswith(d):
            return url
    return ''


def get_status(url):
    try:
        resp = http.client.HTTPConnection(url, timeout=timeout)
        resp.request('GET', '/')
        response = resp.getresponse()
        title = extract_title(response.read().decode('utf-8'))
        status = response.status
    except (ConnectionError, OSError) as _:
        status = 1909
        title = 'Unidentified'

    try:
        response = requests.get('https://' + url, timeout=timeout)
        if status > response.status_code:
            title = extract_title(response.text)
            status = response.status_code
        else:
            url = 'http://' + url
    except requests.ConnectionError:
        pass
    finally:
        url = 'https://' + url

    if (verbose and resolved and status != 1909) or (verbose and not resolved):
        temp_status = 'Not Reachable' if status == 1909 else status
        print('\n[-] Checking {}{}\n\t{}[+] Status: {}\n\t[+] Title: {}{}\
            '.format(R, url, Y, temp_status, title, C))

    if (resolved and status != 1909) or not resolved:
        url_report.append(dict(url=url, status=status, title=title))


def extract_title(html_body):
    match = re.search('<title>(.*?)</title>', html_body)
    title = match.group(1) if match else 'Sorry, couldn\'t wait to check ;)'
    return title


def generate_report(*args):
    mode, domain, domain_length, u_report = args
    report = dict(html='', text='')
    domains = ','.join(domain)
    div_code = ''

    if mode == 'passive':
        for url in u_report:
            report['text'] += url + '\n'
            part_div_code = """
    <div><a href='http://www.{}' target='_blank' rel='nofollow noopener\
     noreferrer' class='text'>http://www.{}</a> | <a href='https://www.{}'\
     target='_blank' rel='nofollow noopener noreferrer' class='text'>\
     https://www.{}</a><div class='container'>[Subdomain: '<span\
     style='background-color:yellow'>{}</span>']</div></div>
            """.format(url, url, url, url, url)
            div_code += part_div_code
    elif mode == 'active':
        for u in u_report:
            url = u['url']
            title = u['title']
            status = 'Not Reachable' if u['status'] == 1909 else u['status']
            report['text'] += base_url(url) + '\n'
            part_div_code = """
    <div><a href={} target=_blank rel="nofollow noopener noreferrer"\
     class=text>{}</a> <div class=container> [Subdomain: '<span\
     style=background-color:#ff0>{}</span>'], [Status: '<span\
     style=background-color:#ff0>{}</span>'], [Title: '<span\
     style=background-color:#ff0>{}</span>'] </div></div>
            """.format(url, url, base_url(url), status, title)
            div_code += part_div_code

    style = """\
    h1{font-family:sans-serif}a{color:#000}.text{font-size:16px;\
    font-family:Helvetica,sans-serif;color:#323232;background-color:#fff}\
    .container{background-color:#e9e9e9;padding:10px;margin:10px 0;\
    font-family:helvetica;font-size:13px;border-width:1px;border-style:solid;\
    border-color:#8a8a8a;color:#323232;margin-bottom:15px}\
    .button{padding:17px 60px;margin:10px 10px 10px 0;display:inline-block;\
    background-color:#f4f4f4;border-radius:.25rem;text-decoration:none;\
    -webkit-transition:.15s ease-in-out;transition:.15s ease-in-out;\
    color:#333;position:relative}.button:hover{background-color:#eee;\
    text-decoration:none}.github-icon{line-height:0;position:absolute;\
    top:14px;left:24px;opacity:.7}
    """
    part_code = """\
    <!doctype html>
    <html>
    <head>
    <style>{}</style>
    <title>Sanitiz3r Report - {}</title>
    </head>
    <body>
    <h1>Sanitiz3r Report - {} [{} Subdomain(s)]</h1>
    {}
    <a class=button contenteditable=false href=\
    https://github.com/sawzeeyy/Sanitiz3r/issues/new \
    rel="nofollow noopener noreferrer" target=_blank><span \
    class=github-icon><svg height=24 viewbox="0 0 24 24" width=24 \
    xmlns=http://www.w3.org/2000/svg> <path d="M9 19c-5 1.5-5-2.5-7-3m14 \
    6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 \
    0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 \
    0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 \
    0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" \
    fill=none stroke=#000 stroke-linecap=round stroke-linejoin=round \
    stroke-width=2></path></svg></span> Report an issue.</a>
    </body>
    </html>
    """.format(style, domains, domains, domain_length, div_code)
    report['html'] = part_code
    return report


def save_report(code, filename):
    with open(filename + '.html', 'w') as html:
        html.write(code['html'])

    with open(filename + '.txt', 'w') as text:
        text.write(code['text'])


def sanitiz3r():
    global url_report
    global timeout
    global verbose
    global resolved

    header()
    args = parse_args()
    domain = args.domain.split(',')
    mode = 'active' if args.active else 'passive'
    verbose = args.verbose
    timeout = args.timeout
    resolved = args.resolved

    if isinstance(args.output, str):
        filename = args.output.split('.')[0] + '_sanitiz3r'
    else:
        filename = domain[0].split('.')[0]

    if len(domain) == 1 and domain[0].split('.')[1] == 'txt':
        try:
            domain = open(domain[0]).readlines()
        except IOError:
            print('{}Cannot find : {}{}'.format(R, domain[0], C))
            sys.exit()

    domain = [i.strip() for i in domain]
    file = args.input.split(',')
    urls = get_urls(domain, file)
    filename = os.getcwd() + '/' + filename

    print('{}[+] {} URLs / Subdomains Sanitiz3d'.format(Y, len(urls)))

    if mode == 'passive':
        report = generate_report(mode, domain, len(urls), urls)
        save_report(report, filename)
    elif mode == 'active':
        print('{}[+] Now checking the individual subdomains{}'.format(Y, C))
        url_report = []
        with ThreadPoolExecutor(max_workers=args.thread) as executor:
            executor.map(get_status, urls)

        url_report = sorted(url_report, key=lambda i: i['status'])
        if not url_report:
            print('{}[+] None of the URLs resolved{}'.format(Y, C))
            sys.exit()

        if resolved:
            print('\n{}[+] {} URLs / Subdomains Resolved{}\
                '.format(Y, len(url_report), C))

        report = generate_report(mode, domain, len(url_report), url_report)
        save_report(report, filename)

    print('{}[+] HTML Report Successfully Generated{}'.format(Y, C))
    print('{}[+] File saved to {}{}.html{}'.format(Y, R, filename, C))
    print('{}[+] Sanitiz3r Operation Completed!{}'.format(Y, W))

    try:
        webbrowser.open_new_tab('file:///' + filename + '.html')
    except IOError:
        webbrowser.open_new_tab(filename + '.html')


if __name__ == '__main__':
    sanitiz3r()
