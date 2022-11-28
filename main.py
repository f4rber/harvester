import re
import os
import time
from signal import SIGKILL
import subprocess
import json
import random
import urllib3
import argparse
import telebot
import datetime
from bs4 import BeautifulSoup
from urllib3 import Timeout, Retry
from urllib3.contrib.socks import SOCKSProxyManager
from multiprocessing import Pool, freeze_support

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="verbose", action="store_true")
parser.add_argument("-t", "--threads", help="number of threads (5)", type=int)
parser.add_argument("-o", "--onion", help="tor proxy", action="store_true")
parser.add_argument("-f", "--file", help="urls.txt", type=str, required=True)
args = parser.parse_args()

bot_id = ""
bot = telebot.TeleBot(bot_id, parse_mode=None)
ids = ['']
links = [i.split("\n")[0] for i in open("links.txt", "r").readlines()]
data = json.load(open("apps.json.py", "r"))
ua = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
      'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)']

regex = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
regexes = {
    "GitLab Token": r"gitlab-token.",
    "Slack Token": r"(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key_1": r"((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "Amazon MWS Auth Token": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Amazon AWS URL": r"s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
    "AWS API Key_2": r"AKIA[0-9A-Z]{16}",
    "AWS AppSync GraphQL Key": r"da2-[a-z0-9]{26}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub": r"[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "GitHub Access Token": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
    "Generic API Key": r"[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": r"[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": r"\"type\": \"service_account\"",
    "Google Gmail API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": r"ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Password in URL": r"[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Slack Webhook": r"https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": r"[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twitter Access Token": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": r"[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    'Json web token': r'^[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2}$'
}


def header_gen():
    header = {
        'User-agent': random.choice(ua),
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'keep-alive'}

    try:
        if args.onion:
            http = SOCKSProxyManager("socks5h://127.0.0.1:9050", headers=header, cert_reqs=False, num_pools=30)
        else:
            http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)
    except Exception as ex:
        if args.verbose:
            print(str(ex))
        http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)
    return http


def builtwith(u, headers=None, html=None):
    techs = {}
    # Check URL
    for app_name, app_spec in data['apps'].items():
        if 'url' in app_spec:
            if contains(u, app_spec['url']):
                add_app(techs, app_name, app_spec)

    # Download content
    if None in (headers, html):
        try:
            req = header_gen().request("GET", u, retries=Retry(2), timeout=Timeout(40))
            if headers is None:
                headers = req.headers
            if html is None:
                try:
                    ht = BeautifulSoup(req.data, features="html.parser")
                    html = ht.prettify()
                except:
                    html = req.data.decode("latin-1")
        except Exception as e:
            if "SOCKS" not in str(e) and "retries" not in str(e) and "timeout" not in str(e) and "XMLParsedAsHTMLWarning" not in str(e):
                print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Error with {u}\n{str(e)}")

    # Check headers
    if headers:
        for app_name, app_spec in data['apps'].items():
            if 'headers' in app_spec:
                if contains_dict(headers, app_spec['headers']):
                    add_app(techs, app_name, app_spec)

    # Check html
    if html:
        for app_name, app_spec in data['apps'].items():
            for key in 'html', 'script':
                snippets = app_spec.get(key, [])
                if not isinstance(snippets, list):
                    snippets = [snippets]
                for snippet in snippets:
                    if contains(html, snippet):
                        add_app(techs, app_name, app_spec)
                        break

        # check meta
        # XXX add proper meta data parsing
        if isinstance(html, bytes):
            html = html.decode()
        metas = dict(re.compile('<meta[^>]*?name=[\'"]([^>]*?)[\'"][^>]*?content=[\'"]([^>]*?)[\'"][^>]*?>', re.IGNORECASE).findall(html))
        for app_name, app_spec in data['apps'].items():
            for name, content in app_spec.get('meta', {}).items():
                if name in metas:
                    if contains(metas[name], content):
                        add_app(techs, app_name, app_spec)
                        break
    return techs, html


def add_app(techs, app_name, app_spec):
    for category in get_categories(app_spec):
        if category not in techs:
            techs[category] = []
        if app_name not in techs[category]:
            techs[category].append(app_name)
            implies = app_spec.get('implies', [])
            if not isinstance(implies, list):
                implies = [implies]
            for app_name in implies:
                add_app(techs, app_name, data['apps'][app_name])


def get_categories(app_spec):
    return [data['categories'][str(c_id)] for c_id in app_spec['cats']]


def contains(v, regex):
    if isinstance(v, bytes):
        v = v.decode()
    if len(v) > 870000:
        string_len = len(v)
        part_size = string_len // 1000
        step = part_size
        for _ in range(string_len // part_size):
            part = v[:step]
            v = v[step - 1:]
            step += part_size
            if step > string_len:
                break
            res = re.compile(regex.split('\\;')[0], flags=re.IGNORECASE).search(part)
            if res:
                return res
    else:
        return re.compile(regex.split('\\;')[0], flags=re.IGNORECASE).search(v)


def contains_dict(d1, d2):
    for k2, v2 in d2.items():
        v1 = d1.get(k2)
        if v1:
            if not contains(v1, v2):
                return False
        else:
            return False
    return True


def regex_checker(req, url):
    for reg in regexes.items():
        my_re = re.compile(regex.replace(r'%%regex%%', reg[1]), re.VERBOSE)
        find_regex = my_re.findall(req.data.decode("utf-8", "ignore"))
        if find_regex:
            for find in find_regex:
                if len(find) > 200:
                    continue
                if args.verbose:
                    print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] {url}, {reg[0]}, {find}")
                for id_ in ids:
                    bot.send_message(id_, f"Found by #regex parser ('{reg[0]}:{find}') :\n" + url + f"\nResponse length : {len(req.data)} bytes")
                f = open("reports/report.txt", "a")
                f.write(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by regex parser ('{reg[0]}:{find}') |" + url + f"|Response length : {len(req.data)} bytes")
                f.close()


def scanner(url):
    enabled = open("enabled.txt", "r").read().strip()
    if enabled == "False":
        name = __file__.split("/")[-1]
        pids = subprocess.check_output([f"""ps -aux | grep '{name}' | grep -v 'grep {name}' | awk """ + """'{print $2}'"""], shell=True, stderr=subprocess.STDOUT).decode("utf-8", "ignore").strip().splitlines()
        for pid in pids:
            if int(pid) == os.getpid():
                continue
            os.kill(int(pid), SIGKILL)
        os.kill(os.getppid(), SIGKILL)
        os.kill(os.getpid(), SIGKILL)
    resp_len = 0
    try:
        if "http" not in url:
            url = "http://" + url
        if args.verbose:
            print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Checking {url}")

        builtwith_req, page_html = builtwith(url)
        if args.verbose:
            if builtwith_req:
                print(f"[{datetime.datetime.utcnow().replace(microsecond=0)}] Discovered technologies: {url}\n{builtwith_req}\n")
        if "wikis" in builtwith_req:
            for id_ in ids:
                bot.send_message(id_, f"Found by #technology parser {url}:\n({','.join(builtwith_req['wikis'])})")
            f = open(f"reports/wikis.txt", "a", encoding="utf-8")
            f.write(f"{url}|{','.join(builtwith_req['wikis'])}\n")
        if "lms" in builtwith_req:
            for id_ in ids:
                bot.send_message(id_, f"Found by #technology parser {url}:\n({','.join(builtwith_req['lms'])})")
            f = open(f"reports/lms.txt", "a", encoding="utf-8")
            f.write(f"{url}|{','.join(builtwith_req['lms'])}\n")
        if "web-servers" in builtwith_req:
            for id_ in ids:
                bot.send_message(id_, f"Found by #technology parser {url}:\n({','.join(builtwith_req['web-servers'])})")
            f = open(f"reports/web-servers.txt", "a", encoding="utf-8")
            f.write(f"{url}|{','.join(builtwith_req['web-servers'])}\n")
        if "programming-languages" in builtwith_req:
            for id_ in ids:
                bot.send_message(id_, f"Found by #technology parser {url}:\n({','.join(builtwith_req['programming-languages'])})")
            f = open(f"reports/programming-languages.txt", "a", encoding="utf-8")
            f.write(f"{url}|{','.join(builtwith_req['programming-languages'])}\n")
        if "cms" in builtwith_req:
            for id_ in ids:
                bot.send_message(id_, f"Found by #technology parser {url}:\n({','.join(builtwith_req['cms'])})")
            f = open(f"reports/cms.txt", "a", encoding="utf-8")
            f.write(f"{url}|{','.join(builtwith_req['cms'])}\n")
        if "web-frameworks" in builtwith_req:
            for id_ in ids:
                bot.send_message(id_, f"Found by #technology parser {url}:\n({','.join(builtwith_req['web-frameworks'])})")
            f = open(f"reports/web-frameworks.txt", "a", encoding="utf-8")
            f.write(f"{url}|{','.join(builtwith_req['web-frameworks'])}\n")

        if page_html:
            all_script_tags = BeautifulSoup(page_html, features="html.parser").find_all('script', {"src": True})
            for js in all_script_tags:
                if js['src'].startswith("//"):
                    if args.verbose:
                        print(f"[{datetime.datetime.utcnow().replace(microsecond=0)}] Found js file: {url}{'/'.join(js['src'].split('/')[1:])}")
                    req_js = header_gen().request("GET", url + '/'.join(js['src'].split('/')[1:]), retries=Retry(2), timeout=Timeout(30))
                    regex_checker(req_js, url + '/'.join(js['src'].split('/')[1:]))
                elif js['src'].startswith("/"):
                    if args.verbose:
                        print(f"[{datetime.datetime.utcnow().replace(microsecond=0)}] Found js file: {url}{js['src']}")
                    req_js = header_gen().request("GET", url + js['src'], retries=Retry(2), timeout=Timeout(30))
                    regex_checker(req_js, url + js['src'])
                elif js['src'].startswith("http"):
                    if args.verbose:
                        print(f"[{datetime.datetime.utcnow().replace(microsecond=0)}] Found js file: {js['src']}")
                    req_js = header_gen().request("GET", js['src'], retries=Retry(2), timeout=Timeout(30))
                    regex_checker(req_js, js['src'])
                else:
                    if args.verbose:
                        print(f"[{datetime.datetime.utcnow().replace(microsecond=0)}] Found js file: {url}/{js['src']}")
                    req_js = header_gen().request("GET", url + "/" + js['src'], retries=Retry(2), timeout=Timeout(30))
                    regex_checker(req_js, url + "/" + js['src'])

        for link in links:
            if "|" in link:
                req = header_gen().request("GET", url + link.split("|")[0], retries=Retry(2), timeout=Timeout(30))
                if req.status == 200 and 10 < len(req.data) != resp_len and len(req.data) < 4000:
                    if args.verbose:
                        print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by status code ('{req.status}') : " + url + link.split("|")[0] + f"\nResponse length : {len(req.data)} bytes")
                    f = open("reports/report.txt", "a")
                    f.write(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by status code ('{req.status}') |" + url + link.split("|")[0] + f"|Response length : {len(req.data)} bytes\n")
                    f.close()
                    resp_len = len(req.data)
                if "+" in link.split("|")[1]:
                    if link.split("|")[1].split("+")[1] in req.data.decode("utf-8", "ignore"):
                        if args.verbose:
                            print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by #ontent parsing ('{link.split('|')[1].split('+')[1]}') : " + url + link.split("|")[0] + f"\nResponse length : {len(req.data)} bytes")
                        for id_ in ids:
                            bot.send_message(id_, f"Found by #content parsing ('{link.split('|')[1].split('+')[1]}') :\n" + url + link.split("|")[0] + f"\nResponse length : {len(req.data)} bytes")
                        f = open("reports/report.txt", "a")
                        f.write(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by content parsing ('{link.split('|')[1].split('+')[1]}') |" + url + link.split("|")[0] + f"|Response length : {len(req.data)} bytes\n")
                        f.close()
                elif "regex" in link.split("|")[1]:
                    regex_checker(req, url + link.split("|")[0])
            else:
                req = header_gen().request("GET", url + link, retries=Retry(2), timeout=Timeout(20))
                if req.status == 200 and resp_len != len(req.data) and len(req.data) < 4000:
                    if args.verbose:
                        print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by status code ('{req.status}') : " + url + link + f"\nResponse length : {len(req.data)} bytes")
                    for id_ in ids:
                        bot.send_message(id_, f"Found by #status code ('{req.status}') :\n" + url + link + f"\nResponse length : {len(req.data)} bytes")
                    f = open("reports/report.txt", "a")
                    f.write(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Found by status code ('{req.status}') :\n" + url + link + f"|Response length : {len(req.data)} bytes\n")
                    f.close()
                    resp_len = len(req.data)
            f = open(f"reports/status/status_{req.status}.txt", "a", encoding="utf-8")
            f.write(f"{url + link}\n")
            f.close()

        f = open("reports/checked.txt", "a", encoding="utf-8")
        f.write(f"{url}\n")
        f.close()

    except Exception as ex:
        f = open("reports/checked.txt", "a", encoding="utf-8")
        f.write(f"{url}\n")
        f.close()
        if args.verbose:
            if "SOCKS" not in str(ex) and "retries" not in str(ex) and "timeout" not in str(ex) and "XMLParsedAsHTMLWarning" not in str(ex):
                print(f"\n[{datetime.datetime.utcnow().replace(microsecond=0)}] Error with {url}\n{str(ex)}")


if __name__ == "__main__":
    urls = [i.split("\n")[0] for i in open(args.file, "r").readlines()]
    if args.file:
        if args.threads:
            freeze_support()
            pool = Pool(args.threads)
            pool.map(scanner, urls)
            pool.close()
            pool.join()
        else:
            for i in urls:
                scanner(i)
