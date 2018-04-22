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
import json
import ast

class main_gui:
    def __init__(self, root):
        ip_addr_verify = True
        self.root = root
        while True:
            self.root.focus_set()
            if ip_addr_verify == True:
                ip_addr = askstring('IP Address', "Enter Your Server's IP Address")
            elif ip_addr_verify == 'INVALID':
                ip_addr = askstring('Invalid IP Address', "Invalid IP Address \n Please Enter Your Server's IP Address")
            elif ip_addr_verify == 'CONNECTION':
                ip_addr = askstring("Connection Problem",
                                    "Couldn't Connect To IP Address \n Please Reenter Your Server's IP Address")
            if ip_addr == None:
                os._exit(0)

            if self.check_ip(ip_addr):
                self.s = socket.socket()
                self.s.settimeout(0.3)
                try:
                    self.s.connect((ip_addr, port))
                    self.s.settimeout(None)
                    break
                except:
                    ip_addr_verify = 'CONNECTION'
                    continue
            else:
                ip_addr_verify = 'INVALID'
        self.root.focus_set()
        user_login_selection = register_login_popup(self.root, self.s.recv(2)).show()
        if user_login_selection != None:
            self.s.send(user_login_selection)
        else:
            self.s.send(None)

            os._exit(0)
        if user_login_selection == 'r':
            times = 0
            while True:
                if times == 0:
                    username = askstring('Username', 'Enter Your Desired Username')
                elif times == 'EMPTY':
                    username = askstring('Username', 'Empty Username Entered')
                    times = 1
                elif times >= 1 and type(times) == int:
                    username = askstring('Username', 'Username Taken \nEnter Another Username')
                if username == None:
                    os._exit(0)
                print username
                if len(username) == 0:
                    times = 'EMPTY'
                    continue
                self.s.send(username)
                code = self.s.recv(2048)
                if code == 'VALID':
                    while True:
                        password = password_input(self.root, 'Enter Your Desired Password').show()
                        if password != None:
                            break
                        else:
                            os._exit(0)
                    self.s.send(hashlib.sha256(password).hexdigest())
                    break
                else:
                    times += 1
            self.root.deiconify()
        elif user_login_selection == 'l':
            self.s.setblocking(True)
            worked = get_login_info(root, self.s).show()
            if not worked:
                os._exit(0)
        self.textbox_frame = Frame(root, width=70)
        self.textbox_frame.grid(row=0)
        self.root.columnconfigure(1, weight=1)
        self.txtbx = ScrolledText(self.textbox_frame)
        self.txtbx.see(END)
        self.txtbx.pack(fill=BOTH)

        self.bottom_row = Frame(root, width=70, height=20)
        self.e = Entry(self.bottom_row, width=70)
        self.e.pack(fill='both', expand=1)

        self.butt = Button(root, text='Send', command=self.send_msg)
        self.root.focus_set()
        self.root.bind('<Return>', self.send_msg)
        self.butt.grid(column=1)
        self.schedule_queue = Queue.Queue()
        self.update_from_queue()
        self.bottom_row.grid(row=1)

        threading.Thread(target=self.recv_thread).start()
        self.e.focus_set()

        root.bind('<Control-KeyRelease-a>', self.select_all)

    def select_all(self, event):
        self.e.select_range(0, END)
        self.e.icursor(len(self.e.get()))

    def check_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

    def recv_thread(self):
        while True:
            try:
                data = self.s.recv(300000)
                if data:
                    sent_json = json.loads(data)
                    if sent_json['type'] == 'TEXT':
                        try:
                            self.schedule_queue.put(zlib.decompress(ast.literal_eval(sent_json['msg'])))
                        except:
                            self.schedule_queue.put(ast.literal_eval(sent_json['msg']))
            except socket.error:
                self.schedule_queue.put('Server Disconnect')
            except Exception, e:
                print repr(e)
                os._exit(0)

    def update_from_queue(self):
        try:
            while True:
                line = self.schedule_queue.get_nowait()
                if line != 'Server Disconnect':
                    self.txtbx.config(state=NORMAL)
                    # Temporarily Inserts Line In For Refresh of Coloring To Get All Lines
                    self.txtbx.insert(END, line + '\n')
                    self.refresh_coloring()
                    self.txtbx.config(state=DISABLED)
                    self.txtbx.see('end')
                else:
                    showerror('Server', 'Server Has Disconnected')
                    os._exit(0)
        except Queue.Empty:
            pass
        root.after(100, self.update_from_queue)

    def send_msg(self, event=None):
        if len(self.e.get()) == 0:
            showwarning("Warning", "Can't Send Empty Message")
            return None
        else:
            txt = self.e.get()
            if len(txt) > 170:
                txt = zlib.compress(txt, 9)
            data = {'type': 'TEXT', 'msg': txt}
            self.s.send(json.dumps(data))
            self.schedule_queue.put('[' + strftime('%m/%d/%Y %I:%M:%S') + ']~ ME: ' + self.e.get())
            self.e.delete(0, END)

    def refresh_coloring(self):
        lines = self.txtbx.get('1.0', 'end-1c').splitlines()
        self.txtbx.delete('1.0', END)
        self.txtbx.tag_config('others', background='gray77', foreground='black')
        self.txtbx.tag_config('server', background='yellow', foreground='red')
        self.txtbx.tag_config('user', background='#005ff9', foreground='#000000')
        for i in lines:
            if i:
                line = i + '\n'
                if ']~ SERVER: ' in i:
                    self.txtbx.insert(END, line, 'server')
                elif ']~ ME: ' in i:
                    self.txtbx.insert(END, line, 'user')
                else:
                    self.txtbx.insert(END, line, 'others')


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
        if self.choice == '':
            os._exit(1)
        else:
            return self.choice


class get_login_info:
    def __init__(self, root, sock):
        self.sock = sock
        master = Toplevel(root)
        self.master = master
        self.worked = False
        Label(master, text='Username: ').grid(row=0, column=0)
        self.username_ent = Entry(master)
        self.username_ent.focus_set()
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
                elif response == 'LOGGEDIN':
                    showerror('Already Logged In', 'You Or Someone Else Has Already Logged In!')
                else:
                    showerror('Username Not Found', "Username Not Found")
            else:
                showerror('Empty Password', "You Didn't Enter In A Password!")
        else:
            showerror('Empty Username', "You Didn't Enter in a Username!")

    def show(self):
        self.master.deiconify()
        self.master.wait_window()
        return self.worked


class password_input:
    def __init__(self, root, t):
        self.final_pswd = ''
        self.master = Toplevel(root)
        master = self.master
        master.focus_set()
        Label(master, text=t).grid(row=0)
        Label(master, text='Password: ').grid(row=1, column=0)
        self.pswd = Entry(master, show='*')
        self.pswd.focus_set()
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
    root.title('Python Simple Chatroom')
    port = 5000
    main_gui(root)
    root.mainloop()
    os._exit(0)
