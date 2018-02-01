import socket
import threading
from time import strftime, sleep
import sys
import netifaces
import atexit
import random
import hashlib
import zlib


# TODO: Handle Multiple People Signing In w/ The Same Name

def get_ip():
    if sys.platform != 'win64' and sys.platform != 'win32':
        interfaces = netifaces.interfaces()
        if 'eth0' in interfaces:
            return netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']
        elif 'wlan0' in interfaces:
            return netifaces.ifaddresses('wlan0')[netifaces.AF_INET][0]['addr']
        else:
            return netifaces.ifaddresses(interfaces[0])[netifaces.AF_INET][0]['addr']
    else:
        return socket.gethostbyname(socket.getfqdn())


def parse_transcript(username):
    with open('transcript.txt', 'r') as f:
        lines = f.readlines()
    new_lines = []
    for i in lines:
        if 'Startup' in i:
            continue
        if username in i and ('SERVER' not in i):
            new_lines.append(i.replace(username, 'ME'))
        else:
            new_lines.append(i)
    # print lines
    return new_lines


def client(conn, u):
    global conns
    try:
        full = ''
        for i in parse_transcript(u):
            full += i.strip('\n') + '\n'
        compressed = zlib.compress(full,9)
        conn.send(compressed)
    except:
        remover(conn, conn.getpeername())
    sleep(.5)
    f = addr_to_user.values()
    try:
        del f[f.index(u)]
    except:
        pass
    f = ', '.join(f)
    try:
        if len(f) != 0:
            conn.send('Other People Online Are ' + f)
        else:
            conn.send('No One Else Is Currently Online')
    except:
        remover(conn, conn.getpeername())
    try:
        while True:
            data = conn.recv(8192)
            if data:
                try:
                    data = zlib.decompress(data)
                except:
                    pass
                msg = '[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ ' + u + ': ' + data
                send_all(msg, conn)
                print msg
            else:
                try:
                    remover(conn, conn.getpeername())
                except:
                    pass
    except:
        remover(conn, conn.getpeername())


def remover(c, addr):
    conns.remove(c)
    print addr
    print '[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ SERVER: ' + addr_to_user[addr] + ' Has Disconnected'
    send_all('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ SERVER: ' + addr_to_user[addr] + ' Has Disconnected', s)
    del addr_to_user[addr]


def send_all(msg, conn):
    global conns
    f = open('transcript.txt', 'a')
    f.write(msg + '\n')
    f.close()
    for i in conns:
        try:
            if i != conn:
                if len(msg) <= 170:
                    i.send(msg)
                else:
                    i.send(zlib.compress(msg,9))
            else:
                pass
        except:
            remover(conn, addr_to_user[conn.getpeername()])


def generate_salt(char_amount=32, suitable_chars="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()"):
    final = ""
    r = random.SystemRandom()
    for i in xrange(0, char_amount):
        final += r.choice(suitable_chars)
    return final


def handle_conn(conn, addr):
    #Handles Any User Disconnects Between Verification
    try:
        login_or_username = conn.recv(1024)
        if login_or_username == None:
            return None
        elif login_or_username == 'r':
            usernames = []
            try:
                with open('usernames.dat', 'r') as f:
                    for i in f.readlines():
                        usernames.append(i.strip('\n'))
            except:
                usernames = []
            while True:
                username = conn.recv(1024)
                for i in usernames:
                    splitted = i.split('`')
                    if splitted[0] == username:
                        conn.send('EXISTING')
                else:
                    conn.send('VALID')
                    password = conn.recv(4096)
                    break
            with open('usernames.dat','a+') as f:
                salt = generate_salt()
                f.write(username+'`'+hashlib.sha256(password+salt).hexdigest()+'`'+salt+'\n')
                print '[' + strftime('%m/%d/%Y %I:%M:%S') + ']~' + ' Connection ' + addr[0] + ' ---> ' + username
                send_all('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ ' + 'SERVER: ' + username + ' Has Connected', conns)
                addr_to_user[addr] = username
                conns.append(conn)
                threading._start_new_thread(client, (conn, username))
        elif login_or_username == 'l':
            logins = []
            with open('usernames.dat','r') as f:
                for i in f.readlines():
                    logins.append(i.strip('\n'))
            while True:
                username = conn.recv(2048)
                print 'username:',username
                if username == None:
                    return None
                for i in logins:
                    stored_username = i.split('`')[0]
                    print stored_username
                    print stored_username, '==',username,stored_username == username
                    if stored_username == username:
                        conn.send('VALID')
                        break
                else:
                    conn.send('INVALID')
                    continue
                hashed_pswd = conn.recv(2048)
                if hashed_pswd == None:
                    return None
                for i in logins:
                    splitted = i.split('`')
                    if hashlib.sha256(hashed_pswd+splitted[2]).hexdigest() == splitted[1] and splitted[0] == username:
                        conn.send('VALID')
                        break
                else:
                    conn.send('INVALID')
                print '[' + strftime('%m/%d/%Y %I:%M:%S') + ']~' + ' Connection ' + addr[0] + ' ---> ' + username
                send_all('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ ' + 'SERVER: ' + username + ' Has Connected', conns)
                addr_to_user[addr] = username
                conns.append(conn)
                threading._start_new_thread(client, (conn, username))
                break
    except Exception, e:
        print e
        return None

if __name__ == '__main__':
    f = open('transcript.txt', 'a+')
    f.write('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~' + ' Startup\n')
    f.close()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print get_ip()
    s.bind((get_ip(), 9001))
    s.listen(500)
    global conns, addr_to_user
    conns = []
    addr_to_user = {}
    while True:
        conn, addr = s.accept()
        try:
            open('usernames.dat','r').close()
            conn.send('1')
        except:
            conn.send('0')
        threading._start_new_thread(handle_conn, (conn, addr))
