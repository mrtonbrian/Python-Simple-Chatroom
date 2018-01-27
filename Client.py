try:
    from tkMessageBox import *
    from Tkinter import *
except ImportError:
    from tkinter import *
from ScrolledText import ScrolledText
import socket
import threading
from time import strftime,sleep
import Queue
import os
def recv_thread(conn,q):
    while True:
        try:
            data = conn.recv(4096)
            if data:
                q.put(data)
        except socket.error:
            q.put('Server Disconnect')

def send_msg(txtbx):
    global s,e
    if len(e.get()) == 0:
        showwarning("Warning","Can't Send Empty Message")
        return None
    else:
        s.send(e.get())
        txtbx.config(state=NORMAL)
        txtbx.insert(END, '\n' + '['+strftime('%m/%d/%Y %I:%M:%S')+']~ ME: '+ e.get())
        txtbx.config(state=DISABLED)
        e.delete(0,END)
def update_from_queue():
    global schedule_queue,txtbx
    try:
        while True:
            line = schedule_queue.get_nowait()
            if line != 'Server Disconnect':
                txtbx.config(state=NORMAL)
                txtbx.insert(END,'\n'+line)
                txtbx.config(state=DISABLED)
            else:
                showerror('Server','Server Has Disconnected')
                os._exit(0)
    except Queue.Empty:
        pass
    root.after(100,update_from_queue)
def GUI(window):
    global e,s,schedule_queue,txtbx
    txtbx = ScrolledText(window, state=DISABLED)
    txtbx.grid(row=0)
    txtbx.see(END)
    e = Entry(window)
    e.grid(row=1, column=0)
    butt = Button(window, text='Send', command=lambda:send_msg(txtbx))
    window.bind('<Return>',lambda event: send_msg(txtbx))
    butt.grid(row=1, column=1)
    schedule_queue = Queue.Queue()
    update_from_queue()
    sleep(.3)
    threading.Thread(target=lambda: recv_thread(s,schedule_queue)).start()
if __name__ == '__main__':
    ip_addr = raw_input('IP Address: ')
    username = raw_input('Username: ')
    port = 9001
    global s
    s = socket.socket()
    s.connect((ip_addr, port))
    sleep(.3)
    s.send(username)
    root = Tk()
    GUI(root)
    root.mainloop()
    s.close()
    os._exit(0)