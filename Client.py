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
import hashlib
import zlib


# https://stackoverflow.com/a/29126154/8935887
class register_login_popup:
    def __init__(self, root, usernames):
        self.choice = ''
        self.master = Toplevel(root)
        master = self.master
        Label(master, text='Register Or Login?').grid(row=0, column=1)
        Button(master, text='Register', command=lambda: self.set_choice('r')).grid(row=1, column=0)
        login_butt = Button(master, text='Login', command=lambda: self.set_choice('l'))
        login_butt.grid(row=1, column=2)
        master.focus_set()
        if usernames == '0':
            login_butt['state'] = DISABLED

    def set_choice(self, c):
        self.master.destroy()
        self.choice = c

    def show(self):
        self.master.wm_deiconify()
        self.master.wait_window()
        return self.choice


def recv_thread(conn, q):
    while True:
        try:
            data = conn.recv(8192)
            if data:
                try:
                    q.put(zlib.decompress(data))
                except:
                    q.put(data)
        except socket.error, e:
            print repr(e)
            q.put('Server Disconnect')


def send_msg(txtbx,s):
    global e
    if len(e.get()) == 0:
        showwarning("Warning", "Can't Send Empty Message")
        return None
    else:
        txt = e.get()
        if len(txt) >= 170:
            txt = zlib.compress(txt, 9)
        s.send(txt)
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


class get_login_info:
    def __init__(self, root, sock):
        self.sock = sock
        master = Toplevel(root)
        self.master = master
        self.worked = False
        Label(master, text='Username: ').grid(row=0, column=0)
        self.username_ent = Entry(master)
        self.username_ent.grid(row=0, column=1)

        Label(master, text='Password').grid(row=1, column=0)
        self.pass_ent = Entry(master, show='*')
        self.pass_ent.grid(row=1, column=1)

        Button(master, text='Login', command=self.check_login_credentials).grid(row=2)

    def check_login_credentials(self):
        if len(self.username_ent.get()) != 0:
            if len(self.pass_ent.get()) != 0:
                self.sock.send(self.username_ent.get())
                print self.username_ent.get()
                response = self.sock.recv(2048)
                if response == 'VALID':
                    self.sock.send(hashlib.sha256(self.pass_ent.get()).hexdigest())
                    response = self.sock.recv(2048)
                    if response == 'VALID':
                        self.worked = True
                        self.master.destroy()
                    else:
                        showerror('Password', 'Incorrect Password!')
                else:
                    showerror('Username Not Found')
            else:
                showerror('Empty Password', "You Didn't Enter In A Password!")
        else:
            showerror('Empty Username', "You Didn't Enter in a Username!")

    def show(self):
        self.master.deiconify()
        self.master.wait_window()
        return self.worked


def GUI(window):
    global e, schedule_queue, txtbx
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
    user_login_selection = register_login_popup(root, s.recv(2)).show()
    if user_login_selection != None:
        s.send(user_login_selection)
    else:
        s.send(None)
        os._exit(0)
    if user_login_selection == 'r':
        times = 0
        while True:
            if times == 0:
                username = askstring('Username', 'Enter Your Desired Username')
            elif times == 'EMPTY':
                username = askstring('Username','Empty Username Entered')
                times = 1
            elif times >= 1 and type(times) == int:
                username = askstring('Username', 'Username Taken \nEnter Another Username')
            print username
            if len(username) == 0:
                times = 'EMPTY'
                continue
            s.send(username)
            code = s.recv(2048)
            if code == 'VALID':
                while True:
                    password = password_input(root, 'Enter Your Desired Password').show()
                    if password != None:
                        break
                    else:
                        os._exit(0)
                s.send(hashlib.sha256(password).hexdigest())
                break
            else:
                times += 1
        root.deiconify()
    elif user_login_selection == 'l':
        s.setblocking(True)
        worked = get_login_info(root,s).show()
        if not worked:
            os._exit(0)
    textbox_frame = Frame(window, width=70)
    textbox_frame.grid(row=0)
    window.columnconfigure(1, weight=1)
    txtbx = ScrolledText(textbox_frame)
    txtbx.see(END)
    txtbx.pack(fill=BOTH)

    bottom_row = Frame(window, width=70, height=20)
    e = Entry(bottom_row, width=70)
    e.pack(fill='both', expand=1)

    butt = Button(window, text='Send', command=lambda: send_msg(txtbx,s))
    window.bind('<Return>', lambda event: send_msg(txtbx))
    butt.grid(column=1)
    schedule_queue = Queue.Queue()
    update_from_queue()
    bottom_row.grid(row=1)

    threading.Thread(target=lambda: recv_thread(s, schedule_queue)).start()
    e.focus_set()


class password_input:
    def __init__(self, root, t):
        self.final_pswd = ''
        self.master = Toplevel(root)
        master = self.master
        master.focus_set()
        Label(master, text=t).grid(row=0)
        Label(master, text='Password: ').grid(row=1, column=0)
        self.pswd = Entry(master, show='*')
        self.pswd.grid(row=1, column=1)
        Label(master, text='Reenter Your Password: ').grid(row=2, column=0)
        self.reentered = Entry(master, show='*')
        self.reentered.grid(row=2, column=1)
        Button(master, text='OK', command=self.on_ok).grid(row=3)
        master.bind('<Return>', lambda event: self.on_ok)

    def on_ok(self):
        inp_pswd = self.pswd.get()
        reentered_pswd = self.reentered.get()
        if inp_pswd != '' and reentered_pswd != '':
            if inp_pswd == reentered_pswd:
                self.final_pswd = self.pswd.get()
                self.master.destroy()
            else:
                showerror('Password', "Passwords Don't Match")
        else:
            showerror('Error', "You Didn't Enter Anything")

    def show(self):
        self.master.wm_deiconify()
        self.master.wait_window()
        return self.final_pswd


if __name__ == '__main__':
    root = Tk()
    port = 9001
    GUI(root)
    root.mainloop()
    os._exit(0)
