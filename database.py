import os
import sqlite3, json, requests
from bs4 import BeautifulSoup
URL = "https://httpd.apache.org/security/json"
# 196 cve's
# List of sets
# Set :
# Dictionary - Key-value pairs
"""
CVE_item = {
        1. CVE Name
        2. CVE Description
        3. CVE Fix Release date
        4. CVE Date log
        5. Version
        6. CVE Vuls
}
"""

# Add all CVE to Database
def main():
    # Connect to database
    conn = sqlite3.connect('apache_cve.db')
    # Create a cursor
    c = conn.cursor()
    if not (os.path.isfile('./apache_cve.db')):
        create_db()
    CVE_list = []
    req = requests.get(URL)
    soup = BeautifulSoup(req.text, "html.parser")
    i = 0
    print("The href links are :")             
    for link in soup.find_all('a'):
        if "CVE" in link.get('href'):
            i += 1
            print(f"{i} Done!\n")
            #print(f"{CVE_list}\n\n")
            #print(link.get('href'))
            cve_name = str(link.get('href'))
            cve_fix_date1 = ""
            cve_fix_date2 = ""
            tmpUrl = str(f"{URL}/{cve_name}")
            print(f"{cve_name}\t:\t{tmpUrl}\n")
            html_content = requests.get(tmpUrl)
            soup2 = BeautifulSoup(html_content.text, 'html.parser')
            json_content = json.loads(soup2.text)
            cve_description = ""
            for fix_date in json_content['timeline'] :
                # Confirm apache2.0 issue (Add for apache1.0)
                if fix_date.get('value')[0].isdigit() :
                    cve_version = str(fix_date.get('value')).split(" ")
                    cnum = int(fix_date.get('value')[0])
                    if cnum == 1:
                        cve_fix_date1 = fix_date.get('time')
                    if cnum == 2:
                        cve_fix_date2 = fix_date.get('time')

                #if str(fix_date.get('value'))[0].isdigit():
            for cve_desc in json_content['description'].get('description_data'): 
                cve_description = cve_desc.get('value')
            #CVE_item = {"cve_name": cve_name, "cve_description": cve_description, "cve_fix_date1": cve_fix_date1, "cve_fix_date2": cve_fix_date2, "cve_version": cve_version[0]}
            cve_name = cve_name.split('.')
            cve_vuls = []
            for vul in json_content['affects'].get('vendor').get('vendor_data')[0].get('product').get('product_data')[0].get('version').get('version_data'): 
                print(vul.get('version_value'))
                cve_vuls.append(vul.get('version_value'))
            print(cve_vuls)


            # for item in CVE_list:
            c.execute('INSERT INTO apache (cve_name, cve_description, cve_fix_date1, cve_fix_date2, cve_version,cve_vuls) VALUES (?,?,?,?,?,?)',
                [
                cve_name[0],
                cve_description,
                cve_fix_date1,
                cve_fix_date2,
                cve_version[0],
                str(cve_vuls)
                ])
            conn.commit()
    dialog()
    c.close()
    return 0



def create_db():
    # Connect to database
    conn = sqlite3.connect('apache_cve.db')
    # Create a cursor
    c = conn.cursor()
    # Create a Table
    c.execute('''CREATE TABLE apache (
            cve_name text,
            cve_description text,
            cve_fix_date1 text,
            cve_fix_date2 text,
            cve_version text,
            cve_vuls text
        )''')
    # Push the previous commands
    conn.commit()

def dialog():
    vulnerable_cve = []
    print("------------------------------------------------")
    print("---------------\tGal Hindi\t---------------")
    print("------------------------------------------------")
    print("Enter 1 to update DATABASE\nEnter 2 to enter apache version")
    x = input()
    if int(x) == 1:
        main()
    if int(x) == 2:
        print("Please enter Apache version : ")
        user_input = input()
        # Connect to database
        conn = sqlite3.connect('apache_cve.db')
        # Create a cursor
        c = conn.cursor()

        c.execute("SELECT * FROM apache")
        for item in c.fetchall():
            tmp = str(item[5]).replace('\'', '').replace(']', '').replace('[', '').replace(')', '').replace('(', '').replace('"', '').replace(',', '')
            tmp = tmp.split(' ')
            for vul1 in tmp:
                #print(vul1)
                if vul1 == user_input:
                    vulnerable_cve.append(item[0])
        print(f"The user is exposed to : {len(vulnerable_cve)} vulnerabilities")
        cnt = 1
        for k in vulnerable_cve:
            print(f"\n{cnt}. {k}")
            cnt+=1
    
    conn.close()


# Detect website version from URL
"""
# def dialog():
#     print("Enter 1 - to input website url\nEnter 2 - to input apache version")
#     user_input = input()
#     tmp = ""
#     if(user_input == 1):
#         print("Enter website url ( q to return ):\n\tExample - www.clalit.co.il, www.google.com")
#         user_website_url = input()
#         # new_command = str(f"curl --head http://{user_website_url}:80")
#         new_command = str(f"curl -I -L http://{user_website_url}:80")
#         cmd = subprocess.Popen(new_command, shell=True, stdout=subprocess.PIPE,
#                             stderr=subprocess.PIPE, stdin=subprocess.PIPE)
#         output_bytes = cmd.stdout.read() + cmd.stderr.read()
#         output_str = str(output_bytes, 'utf-8')
#         tmpStrt = ""
#         print(output_str)
#         for line in output_str.splitlines():
#             if "server" in line.lower() and 'apache' in line.lower() :
#                 for i in range(len(line)):
#                     if line[i].isdigit() :
#                         tmpStrt = line[i:]
#                         break
#         # Private Function goes here
#     if(user_input == 2):
#         for cve in CVE_list:
#             if isEarlier(cve[2], user_input):
#                 tmp += f"{cve[1]}\n"
#         if len(tmp) > 1:
#             print(f"Website is vulnerable to :\n{tmp}")
#         else:
#             print("Website is up to date, no vulnerabilities were found!")
"""
def isEarlier(date1, date2):
    date11 = "2000-10-13".split('-')
    date1 = date1.split('-')
    date2 = date2.split('-')
    # Compare year
    if date1[0] == date2[0]:
        # Compare months:
        if date1[1] == date2[1]:
            # Comapre days :
            if date1[2] == date2[2]:
                return False
            else:
                return date1[2] < date2[2]
        else:
            return date1[1] < date2[1]
    else:
        return date1[0] < date2[0]

dialog()