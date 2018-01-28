import socket
import threading
from time import strftime, sleep
import sys
import netifaces
import atexit


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
    with open('transcript.txt','r') as f:
        lines = f.readlines()
    new_lines = []
    for i in lines:
        if 'Startup' in i:
            continue
        if username in i and ('SERVER' not in i):
            new_lines.append(i.replace(username,'ME'))
        else:
            new_lines.append(i)
    #print lines
    return new_lines


def client(conn, u):
    global conns
    #conn.send('Welcome To The Chatroom, You Can Now Send / Receive Messages')
    try:
        for i in parse_transcript(u):
            conn.send(i.strip('\n')+'\n')
    except:
        remover(conn,conn.getpeername())
    sleep(.5)
    f = addr_to_user.values()
    del f[f.index(u)]
    f = ', '.join(f)
    try:
        if len(f) != 0:
            conn.send('Other People Online Are ' + f)
        else:
            conn.send('No One Else Is Currently Online')
    except:
        remover(conn,conn.getpeername())
    try:
        while True:
            data = conn.recv(8192)
            if data:
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
                i.send(msg)
            else:
                pass
        except:
            remover(conn, addr_to_user[conn.getpeername()])


if __name__ == '__main__':
    f = open('transcript.txt', 'a+')
    f.write('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~' + ' Startup\n')
    f.close()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print get_ip()
    s.bind((get_ip(), 9001))
    s.listen(500)
    global conns
    conns = []
    addr_to_user = {}
    while True:
        conn, addr = s.accept()
        username = conn.recv(1024)
        print '[' + strftime('%m/%d/%Y %I:%M:%S') + ']~' + ' Connection ' + addr[0] + ' ---> ' + username
        send_all('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ ' + 'SERVER: ' + username + ' Has Connected', conns)
        addr_to_user[addr] = username
        conns.append(conn)
        threading._start_new_thread(client, (conn, username))