import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr, formatdate
import configparser
import os
import time
import threading
import html2text
import socket
import base64
from cryptography.fernet import Fernet

class EmailSender:
    def __init__(self, root):
        self.root = root
        self.root.title("邮件发送工具 By CloudEmail")
        
        # 设置窗口大小和位置
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = 800
        window_height = 600
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # 初始化状态变量
        self.paused = False
        self.stopped = False
        self.current_index = 0
        self.total_recipients = 0
        self.send_interval = 5
        self.config_changed = False
        self.save_timer = None
        self.last_smtp_config = {}
        
        # 初始化配置变量
        self.smtp_server = tk.StringVar()
        self.smtp_port = tk.StringVar(value="465")
        self.smtp_user = tk.StringVar()
        self.smtp_pass = tk.StringVar()
        self.sender_name = tk.StringVar()
        self.subject = tk.StringVar()
        self.content_type = tk.StringVar(value='HTML')

        # 创建GUI
        self.create_gui()
        
        # 加载配置
        self.load_configurations()
        
        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def load_configurations(self):
        """加载所有配置"""
        self.load_smtp_config()
        self.load_email_config()
        
        # 保存初始配置状态
        self.last_smtp_config = {
            'server': self.smtp_server.get().strip(),
            'port': self.smtp_port.get().strip(),
            'user': self.smtp_user.get().strip(),
            'pass': self.smtp_pass.get().strip(),
            'sender_name': self.sender_name.get().strip()
        }

    def load_smtp_config(self):
        """从smtp_settings.ini加载SMTP配置"""
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'smtp_settings.ini')

        try:
            if os.path.exists(config_path):
                config.read(config_path, encoding='utf-8')
                if config.has_section('smtp'):
                    self.smtp_server.set(config.get('smtp', 'server', fallback='').strip())
                    self.smtp_port.set(config.get('smtp', 'port', fallback='465').strip())
                    self.smtp_user.set(config.get('smtp', 'user', fallback='').strip())
                    self.sender_name.set(config.get('smtp', 'sender_name', fallback='').strip())
                    
                    # 处理密码解密
                    encrypted_pass = config.get('smtp', 'pass', fallback='').strip()
                    if encrypted_pass:
                        try:
                            decrypted_pass = self._decrypt_password(encrypted_pass)
                            self.smtp_pass.set(decrypted_pass)
                        except Exception as e:
                            self.smtp_status_label.config(text=f"密码解密失败: {str(e)}")
                    else:
                        self.smtp_pass.set('')
            else:
                # 创建默认配置文件
                config['smtp'] = {
                    'server': '',
                    'port': '465',
                    'user': '',
                    'pass': '',
                    'sender_name': ''
                }
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w', encoding='utf-8') as f:
                    config.write(f)
                
        except Exception as e:
            self.smtp_status_label.config(text=f"加载SMTP配置失败: {str(e)}")

    def load_email_config(self):
        """从email_settings.ini加载邮件内容配置"""
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'email_settings.ini')
        
        try:
            if os.path.exists(config_path):
                config.read(config_path, encoding='utf-8')
                if config.has_section('email'):
                    self.subject.set(config.get('email', 'subject', fallback=''))
                    self.content_type.set(config.get('email', 'content_type', fallback='HTML'))
                    
                    # 加载收件人列表
                    recipients = config.get('email', 'recipients', fallback='')
                    self.recipients.delete('1.0', tk.END)
                    if recipients:
                        self.recipients.insert('1.0', recipients)
                    
                    # 加载邮件正文
                    body = config.get('email', 'body', fallback='')
                    self.editor.delete('1.0', tk.END)
                    if body:
                        self.editor.insert('1.0', body)
            else:
                # 创建默认配置文件
                config['email'] = {
                    'subject': '',
                    'content_type': 'HTML',
                    'body': '',
                    'recipients': ''
                }
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w', encoding='utf-8') as f:
                    config.write(f)
                
        except Exception as e:
            self.email_status_label.config(text=f"加载邮件配置失败: {str(e)}")

    def on_closing(self):
        """窗口关闭时的处理"""
        # 取消任何待处理的定时器
        if self.save_timer:
            self.root.after_cancel(self.save_timer)
            self.save_timer = None

        # 立即保存配置
        if self.config_changed:
            self.save_smtp_config()
        self.save_email_config()

        # 关闭窗口
        self.root.destroy()

    def schedule_save(self):
        """安排延迟保存"""
        # 取消之前的定时器
        if self.save_timer:
            self.root.after_cancel(self.save_timer)
            self.save_timer = None

        # 检查配置是否有变化
        current_config = {
            'server': self.smtp_server.get().strip(),
            'port': self.smtp_port.get().strip(),
            'user': self.smtp_user.get().strip(),
            'pass': self.smtp_pass.get().strip(),
            'sender_name': self.sender_name.get().strip()
        }

        if current_config != self.last_smtp_config:
            self.config_changed = True
            # 设置2秒后保存
            self.save_timer = self.root.after(2000, self.delayed_save_smtp_config)

    def delayed_save_smtp_config(self):
        """延迟保存SMTP配置"""
        if self.config_changed:
            if self.save_smtp_config():
                # 更新最后保存的配置状态
                self.last_smtp_config = {
                    'server': self.smtp_server.get().strip(),
                    'port': self.smtp_port.get().strip(),
                    'user': self.smtp_user.get().strip(),
                    'pass': self.smtp_pass.get().strip(),
                    'sender_name': self.sender_name.get().strip()
                }
                self.config_changed = False
            # 无论成功失败，重置定时器
            self.save_timer = None

    def save_smtp_config(self):
        """保存SMTP配置到smtp_settings.ini"""
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'smtp_settings.ini')
        
        try:
            # 获取配置
            server = self.smtp_server.get().strip()
            port = self.smtp_port.get().strip()
            user = self.smtp_user.get().strip()
            password = self.smtp_pass.get().strip()
            sender_name = self.sender_name.get().strip()
            
            # 加密密码
            encrypted_pass = self._encrypt_password(password) if password else ''
            
            # 保存配置
            config['smtp'] = {
                'server': server,
                'port': port,
                'user': user,
                'pass': encrypted_pass,
                'sender_name': sender_name
            }
            
            # 确保目录存在
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # 写入配置文件
            with open(config_path, 'w', encoding='utf-8') as f:
                config.write(f)
            
            self.smtp_status_label.config(text="SMTP配置已保存")
            return True
            
        except Exception as e:
            self.smtp_status_label.config(text=f"SMTP配置保存失败: {str(e)}")
            return False

    def save_email_config(self):
        """保存邮件配置到email_settings.ini"""
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'email_settings.ini')
        
        try:
            # 获取邮件配置
            subject = self.subject.get().strip()
            recipients = self.recipients.get('1.0', tk.END).strip()
            content_type = self.content_type.get().strip() or 'HTML'
            body = self.editor.get('1.0', tk.END).strip()
            
            # 保存配置
            config['email'] = {
                'subject': subject,
                'content_type': content_type,
                'body': body,
                'recipients': recipients
            }
            
            # 确保目录存在
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # 写入配置文件
            with open(config_path, 'w', encoding='utf-8') as f:
                config.write(f)
            
            self.email_status_label.config(text="邮件配置已保存")
            return True
                
        except Exception as e:
            self.email_status_label.config(text=f"邮件配置保存失败: {str(e)}")
            return False

    def _decrypt_password(self, encrypted_password):
        """解密密码"""
        if not encrypted_password:
            return ''
            
        try:
            key = base64.urlsafe_b64encode(b'pysender_secret_key_12345_67890_abcde'[:32].ljust(32, b'_'))
            f = Fernet(key)
            return f.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            return ''

    def _encrypt_password(self, password):
        """加密密码"""
        if not password:
            return ''
            
        try:
            key = base64.urlsafe_b64encode(b'pysender_secret_key_12345_67890_abcde'[:32].ljust(32, b'_'))
            f = Fernet(key)
            return f.encrypt(password.encode()).decode()
        except Exception as e:
            return ''

    def toggle_password_visibility(self):
        """切换密码显示/隐藏状态"""
        current_show = self.smtp_pass_entry.cget('show')
        if current_show == '*':
            self.smtp_pass_entry.config(show='')
            self.toggle_pass_btn.config(text='🔒')
        else:
            self.smtp_pass_entry.config(show='*')
            self.toggle_pass_btn.config(text='👁')

    def save_and_test(self):
        """保存SMTP配置并测试连接"""
        if self.save_smtp_config():
            self.test_smtp_connection()

    def test_smtp_connection(self):
        """测试SMTP连接"""
        self.smtp_status_label.config(text="正在测试SMTP连接...")
        self.root.update()
        try:
            with smtplib.SMTP_SSL(self.smtp_server.get().strip(), int(self.smtp_port.get().strip())) as server:
                server.login(self.smtp_user.get().strip(), self.smtp_pass.get().strip())
                self.smtp_status_label.config(text="SMTP连接测试成功", foreground="green")
        except Exception as e:
            error_msg = str(e)
            if "getaddrinfo failed" in error_msg:
                error_msg = "无法连接到SMTP服务器，请检查服务器地址和网络连接"
            elif "Connection refused" in error_msg:
                error_msg = "连接被拒绝，请检查端口号是否正确"
            elif "Authentication failed" in error_msg:
                error_msg = "身份验证失败，请检查用户名和密码"
            
            self.smtp_status_label.config(text=f"连接失败: {error_msg}", foreground="red")

    def create_gui(self):
        # 配置根窗口行列权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # SMTP配置区域
        smtp_frame = ttk.LabelFrame(self.root, text="SMTP配置")
        smtp_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
        smtp_frame.columnconfigure(0, weight=1)

        # 创建配置输入框架
        config_frame = ttk.Frame(smtp_frame)
        config_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        config_frame.columnconfigure(1, weight=1)

        # SMTP服务器配置
        ttk.Label(config_frame, text="SMTP服务器:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.smtp_server_entry = ttk.Entry(config_frame, textvariable=self.smtp_server)
        self.smtp_server_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        
        ttk.Label(config_frame, text="端口:").grid(row=0, column=2, sticky="w", padx=(10,0), pady=2)
        self.smtp_port_entry = ttk.Entry(config_frame, textvariable=self.smtp_port, width=8)
        self.smtp_port_entry.grid(row=0, column=3, sticky="w", padx=5, pady=2)

        # 用户名和密码配置
        ttk.Label(config_frame, text="用户名:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.smtp_user_entry = ttk.Entry(config_frame, textvariable=self.smtp_user)
        self.smtp_user_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(config_frame, text="密码:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        pass_frame = ttk.Frame(config_frame)
        pass_frame.grid(row=2, column=1, sticky="ew", padx=5, pady=2)
        pass_frame.columnconfigure(0, weight=1)
        
        self.smtp_pass_entry = ttk.Entry(pass_frame, textvariable=self.smtp_pass, show="*")
        self.smtp_pass_entry.grid(row=0, column=0, sticky="ew")
        self.toggle_pass_btn = ttk.Button(pass_frame, text="👁", width=3, command=self.toggle_password_visibility)
        self.toggle_pass_btn.grid(row=0, column=1, padx=(5,0))

        # 发件人名称配置
        ttk.Label(config_frame, text="发件人名称:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.sender_name_entry = ttk.Entry(config_frame, textvariable=self.sender_name)
        self.sender_name_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=2)

        # 测试按钮和状态标签
        btn_frame = ttk.Frame(smtp_frame)
        btn_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        ttk.Button(btn_frame, text="测试连接", command=self.save_and_test).pack(side="left", padx=(0,10))
        self.smtp_status_label = ttk.Label(btn_frame, text="就绪", anchor="w")
        self.smtp_status_label.pack(side="left", fill="x", expand=True)

        # 自动保存配置 - 使用延迟保存机制
        self.smtp_server.trace_add("write", lambda *args: self.schedule_save())
        self.smtp_port.trace_add("write", lambda *args: self.schedule_save())
        self.smtp_user.trace_add("write", lambda *args: self.schedule_save())
        self.smtp_pass.trace_add("write", lambda *args: self.schedule_save())
        self.sender_name.trace_add("write", lambda *args: self.schedule_save())

        # 邮件内容区域
        email_frame = ttk.LabelFrame(self.root, text="邮件内容")
        email_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        email_frame.columnconfigure(0, weight=1)
        email_frame.rowconfigure(2, weight=1)

        # 收件人列表
        ttk.Label(email_frame, text="收件人列表 (每行一个邮箱地址):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        recipients_frame = ttk.Frame(email_frame)
        recipients_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=2)
        recipients_frame.columnconfigure(0, weight=1)
        
        self.recipients = tk.Text(recipients_frame, wrap=tk.WORD, height=4)
        self.recipients.grid(row=0, column=0, sticky="nsew")
        recipients_scroll = ttk.Scrollbar(recipients_frame, orient="vertical", command=self.recipients.yview)
        recipients_scroll.grid(row=0, column=1, sticky="ns")
        self.recipients.configure(yscrollcommand=recipients_scroll.set)
        
        btn_frame = ttk.Frame(email_frame)
        btn_frame.grid(row=1, column=1, sticky="n", padx=5, pady=2)
        ttk.Button(btn_frame, text="导入收件人", command=self.load_recipients).pack(padx=5, pady=2)

        # 邮件主题和内容类型
        ttk.Label(email_frame, text="邮件主题:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.subject_entry = ttk.Entry(email_frame, textvariable=self.subject)
        self.subject_entry.grid(row=3, column=0, sticky="ew", padx=5, pady=2)
        
        ttk.Label(email_frame, text="内容类型:").grid(row=3, column=1, sticky="w", padx=5, pady=2)
        self.content_type_combobox = ttk.Combobox(
            email_frame, 
            textvariable=self.content_type, 
            values=['HTML', '纯文本'], 
            state='readonly', 
            width=8
        )
        self.content_type_combobox.set('HTML')
        self.content_type_combobox.grid(row=3, column=2, sticky="w", padx=5, pady=2)

        # 邮件正文编辑器
        ttk.Label(email_frame, text="邮件正文:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        editor_frame = ttk.Frame(email_frame)
        editor_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", padx=5, pady=2)
        editor_frame.columnconfigure(0, weight=1)
        editor_frame.rowconfigure(0, weight=1)
        
        self.editor = tk.Text(editor_frame, wrap=tk.WORD)
        self.editor.grid(row=0, column=0, sticky="nsew")
        editor_scroll = ttk.Scrollbar(editor_frame, orient="vertical", command=self.editor.yview)
        editor_scroll.grid(row=0, column=1, sticky="ns")
        self.editor.configure(yscrollcommand=editor_scroll.set)
        
        # 模板操作按钮和状态标签
        btn_frame = ttk.Frame(email_frame)
        btn_frame.grid(row=6, column=0, sticky="ew", padx=5, pady=5)
        ttk.Button(btn_frame, text="加载模板", command=self.load_template).pack(side="left")
        self.email_status_label = ttk.Label(btn_frame, text="就绪", anchor="w")
        self.email_status_label.pack(side="left", padx=(10,0), fill="x", expand=True)

        # 自动保存邮件配置
        self.subject_entry.bind("<FocusOut>", lambda e: self.save_email_config())
        self.content_type_combobox.bind("<<ComboboxSelected>>", lambda e: self.save_email_config())
        self.editor.bind("<FocusOut>", lambda e: self.save_email_config())
        self.recipients.bind("<FocusOut>", lambda e: self.save_email_config())

        # 发送控制区域
        control_frame = ttk.Frame(self.root)
        control_frame.grid(row=2, column=0, pady=10, sticky="ew")
        control_frame.columnconfigure(1, weight=1)

        ttk.Label(control_frame, text="发送间隔(秒):").grid(row=0, column=0, sticky="w", padx=5)
        self.interval_entry = ttk.Entry(control_frame, width=5)
        self.interval_entry.insert(0, "5")
        self.interval_entry.grid(row=0, column=1, sticky="w", padx=5)

        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=0, column=2, sticky="e")
        
        self.start_btn = ttk.Button(btn_frame, text="开始发送", command=self.start_sending)
        self.pause_btn = ttk.Button(btn_frame, text="暂停", command=self.toggle_pause, state='disabled')
        self.stop_btn = ttk.Button(btn_frame, text="停止", command=self.stop_sending, state='disabled')
        
        self.start_btn.pack(side="left", padx=5)
        self.pause_btn.pack(side="left", padx=5)
        self.stop_btn.pack(side="left", padx=5)

        # 进度显示
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.grid(row=3, column=0, sticky="ew", padx=10, pady=5)

        # 发送状态标签
        self.sending_status_label = ttk.Label(self.root, text="就绪", anchor="w")
        self.sending_status_label.grid(row=4, column=0, sticky="ew", padx=10, pady=5)

    def load_recipients(self):
        """加载收件人列表文件"""
        filepath = filedialog.askopenfilename(filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    self.recipients.delete('1.0', tk.END)
                    self.recipients.insert('1.0', content)
                    self.email_status_label.config(text=f"已加载收件人列表：{filepath}")
            except Exception as e:
                messagebox.showerror("错误", f"加载收件人列表失败：{str(e)}")
                self.email_status_label.config(text="加载收件人列表失败")

    def load_template(self):
        """加载HTML模板文件"""
        filepath = filedialog.askopenfilename(filetypes=[("HTML模板", "*.html"), ("所有文件", "*.*")])
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.editor.delete('1.0', tk.END)
                    self.editor.insert(tk.END, f.read())
                    self.email_status_label.config(text=f"已加载模板：{filepath}")
            except Exception as e:
                messagebox.showerror("错误", f"加载模板失败：{str(e)}")
                self.email_status_label.config(text="加载模板失败")

    def toggle_pause(self):
        self.paused = not self.paused
        if self.paused:
            self.pause_btn.config(text="继续")
            self.sending_status_label.config(text="已暂停")
        else:
            self.pause_btn.config(text="暂停")
            self.sending_status_label.config(text=f"发送中 ({self.current_index}/{self.total_recipients})")

    def stop_sending(self):
        self.stopped = True
        self.sending_status_label.config(text=f"已停止 ({self.current_index}/{self.total_recipients})")

    def start_sending(self):
        self.stopped = False
        self.paused = False
        self.current_index = 0
        self.start_btn.config(state='disabled')
        self.pause_btn.config(state='normal')
        self.stop_btn.config(state='normal')
        self.sending_status_label.config(text="初始化发送...")
        self.thread = threading.Thread(target=self.send_emails)
        self.thread.daemon = True  # 确保程序退出时线程也会退出
        self.thread.start()

    def send_emails(self):
        try:
            # 验证SMTP配置
            if not all([self.smtp_server.get().strip(), self.smtp_port.get().strip(),
                       self.smtp_user.get().strip(), self.smtp_pass.get().strip()]):
                self.sending_status_label.config(text="错误：SMTP配置不完整")
                return

            # 验证邮件内容
            if not self.subject.get().strip() or not self.editor.get('1.0', tk.END).strip():
                self.sending_status_label.config(text="错误：邮件主题或正文为空")
                return

            # 验证收件人列表
            recipients = [line.strip() for line in self.recipients.get('1.0', tk.END).splitlines() if line.strip()]
            self.total_recipients = len(recipients)
            if not self.total_recipients:
                self.sending_status_label.config(text="错误：收件人列表为空")
                return

            # 设置发送间隔
            try:
                self.send_interval = max(1, int(self.interval_entry.get()))
            except ValueError:
                self.sending_status_label.config(text="错误：发送间隔必须是有效的数字")
                return

            smtp_server = self.smtp_server.get().strip()
            smtp_port = int(self.smtp_port.get().strip())
            self.sending_status_label.config(text=f"连接SMTP服务器: {smtp_server}:{smtp_port}...")
            self.root.update()

            try:
                # 创建SMTP连接
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
                server.login(self.smtp_user.get().strip(), self.smtp_pass.get().strip())
                self.sending_status_label.config(text="开始发送邮件...")
                self.root.update()
                
                # 逐个发送邮件
                for idx, email in enumerate(recipients):
                    if self.stopped:
                        break
                        
                    # 处理暂停状态
                    while self.paused and not self.stopped:
                        time.sleep(0.5)
                        continue
                    
                    # 构建当前邮件的状态信息
                    current_status = f"正在发送 {idx+1}/{self.total_recipients} 到: {email}"
                    self.sending_status_label.config(text=current_status)
                    self.root.update()
                    
                    try:
                        # 构建邮件
                        msg = MIMEMultipart('alternative')
                        sender_name = self.sender_name.get().strip() or self.smtp_user.get().strip()
                        msg['From'] = formataddr((str(Header(sender_name, 'utf-8')), self.smtp_user.get().strip()))
                        msg['To'] = email
                        msg['Subject'] = Header(self.subject.get().strip(), 'utf-8')
                        msg['Date'] = formatdate(localtime=True)

                        # 添加邮件内容
                        content = self.editor.get('1.0', tk.END).strip()
                        if self.content_type.get() == 'HTML':
                            # 添加HTML和纯文本版本
                            plain_text = html2text.html2text(content)
                            msg.attach(MIMEText(plain_text, 'plain', 'utf-8'))
                            msg.attach(MIMEText(content, 'html', 'utf-8'))
                        else:
                            msg.attach(MIMEText(content, 'plain', 'utf-8'))

                        # 发送邮件
                        server.send_message(msg)
                        
                        # 更新进度
                        self.current_index = idx + 1
                        progress_percent = (self.current_index / self.total_recipients) * 100
                        self.progress['value'] = progress_percent
                        status_text = f"已发送 {self.current_index}/{self.total_recipients} ({progress_percent:.1f}%)"
                        self.sending_status_label.config(text=status_text)
                        
                    except Exception as e:
                        # 单个邮件发送失败，记录错误但继续发送
                        error_msg = f"发送到 {email} 失败: {str(e)}"
                        self.sending_status_label.config(text=error_msg)
                    
                    # 更新界面
                    self.root.update_idletasks()
                    
                    # 等待发送间隔（最后一封邮件不需要等待）
                    if not self.stopped and idx < len(recipients) - 1:
                        time.sleep(self.send_interval)
                
                # 关闭SMTP连接
                server.quit()
                
                if self.stopped:
                    self.sending_status_label.config(text=f"已停止 ({self.current_index}/{self.total_recipients})")
                else:
                    self.sending_status_label.config(text=f"发送完成 ({self.current_index}/{self.total_recipients})")
                    
            except Exception as e:
                self.sending_status_label.config(text=f"发送过程中出错: {str(e)}")
                
        finally:
            # 确保关闭SMTP连接
            try:
                if 'server' in locals() and server:
                    server.quit()
            except:
                pass
            
            # 恢复按钮状态
            self.start_btn.config(state='normal')
            self.pause_btn.config(state='disabled')
            self.stop_btn.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailSender(root)
    root.mainloop()
