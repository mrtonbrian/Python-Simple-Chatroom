try:
    from tkMessageBox import *
    from Tkinter import *
    from tkSimpleDialog import *
except ImportError:
    from tkinter import *
from ScrolledText import ScrolledText
import socket
import threading
from time import strftime, sleep
import Queue
import os


def recv_thread(conn, q):
    while True:
        try:
            data = conn.recv(8192)
            if data:
                q.put(data)
        except socket.error, e:
            print repr(e)
            q.put('Server Disconnect')


def send_msg(txtbx):
    global s, e
    if len(e.get()) == 0:
        showwarning("Warning", "Can't Send Empty Message")
        return None
    else:
        s.send(e.get())
        txtbx.config(state=NORMAL)
        txtbx.insert(END, '\n' + '[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ ME: ' + e.get())
        txtbx.config(state=DISABLED)
        txtbx.see(END)
        e.delete(0, END)


def update_from_queue():
    global schedule_queue, txtbx
    try:
        while True:
            line = schedule_queue.get_nowait()
            if line != 'Server Disconnect':
                txtbx.config(state=NORMAL)
                txtbx.insert(END, '\n' + line)
                txtbx.config(state=DISABLED)
                txtbx.see('end')
            else:
                showerror('Server', 'Server Has Disconnected')
                os._exit(0)
    except Queue.Empty:
        pass
    root.after(100, update_from_queue)

def check_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False
def GUI(window):
    global e, s, schedule_queue, txtbx
    textbox_frame = Frame(window,width=70)
    textbox_frame.grid(row=0)
    window.columnconfigure(1,weight=1)
    txtbx = ScrolledText(textbox_frame)
    txtbx.see(END)
    txtbx.pack(fill=BOTH)

    bottom_row = Frame(window,width=70,height=20)
    e = Entry(bottom_row,width=70)
    e.pack(fill='both',expand=1)

    butt = Button(window, text='Send', command=lambda: send_msg(txtbx))
    window.bind('<Return>', lambda event: send_msg(txtbx))
    butt.grid(column=1)
    schedule_queue = Queue.Queue()
    update_from_queue()
    bottom_row.grid(row=1)

    threading.Thread(target=lambda: recv_thread(s, schedule_queue)).start()
    e.focus_set()
if __name__ == '__main__':
    root = Tk()
    port = 9001
    global s
    ip_addr_verify = True
    while True:
        root.focus_set()
        if ip_addr_verify == True:
            ip_addr = askstring('IP Address', "Enter Your Server's IP Address")
        elif ip_addr_verify == 'INVALID':
            ip_addr = askstring('Invalid IP Address', "Invalid IP Address \n Please Enter Your Server's IP Address")
        elif ip_addr_verify == 'CONNECTION':
            ip_addr = askstring("Connection Problem",
                                "Couldn't Connect To IP Address \n Please Reenter Your Server's IP Address")
        if ip_addr == None:
            os._exit(0)
        if check_ip(ip_addr):
            s = socket.socket()
            s.settimeout(0.3)
            try:
                s.connect((ip_addr, port))
                s.settimeout(None)
                break
            except:
                ip_addr_verify = 'CONNECTION'
                continue
            else:
                ip_addr_verify = 'INVALID'
    root.focus_set()
    username = askstring('Username', 'Enter Your Desired Username')
    GUI(root)
    s.send(username)
    root.mainloop()
    s.close()
    os._exit(0)
