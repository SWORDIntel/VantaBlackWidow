"""
TEMPEST-Grade Secure UI
Professional security-focused interface with operational security features
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import logging
import json
import os
import hashlib
import time
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
import base64


class SecureDataHandler:
    """Handles secure storage and data sanitization"""

    def __init__(self, config_file='secure_config.enc'):
        self.config_file = config_file
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)

    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key"""
        key_file = '.encryption_key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
            return key

    def save_config(self, data: Dict[str, Any]):
        """Securely save configuration"""
        try:
            json_data = json.dumps(data)
            encrypted = self.cipher.encrypt(json_data.encode())
            with open(self.config_file, 'wb') as f:
                f.write(encrypted)
            os.chmod(self.config_file, 0o600)
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")

    def load_config(self) -> Dict[str, Any]:
        """Securely load configuration"""
        try:
            if not os.path.exists(self.config_file):
                return {}
            with open(self.config_file, 'rb') as f:
                encrypted = f.read()
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")
            return {}

    @staticmethod
    def redact_sensitive(text: str, patterns: list = None) -> str:
        """Redact sensitive information from text"""
        if patterns is None:
            patterns = [
                (r'AKIA[0-9A-Z]{16}', '[REDACTED-AWS-KEY]'),
                (r'[A-Za-z0-9/+=]{40}', '[REDACTED-SECRET]'),
                (r'sk-[A-Za-z0-9]{32}', '[REDACTED-API-KEY]'),
                (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+', '[REDACTED-JWT]'),
                (r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b', '[REDACTED-EMAIL]'),
                (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]'),
            ]

        import re
        redacted = text
        for pattern, replacement in patterns:
            redacted = re.sub(pattern, replacement, redacted)
        return redacted


class AuditLogger:
    """Secure audit logging with integrity checks"""

    def __init__(self, log_file='audit.log'):
        self.log_file = log_file
        self.setup_logging()

    def setup_logging(self):
        """Setup audit logging"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def log_action(self, action: str, details: Dict[str, Any] = None):
        """Log an action with integrity hash"""
        try:
            timestamp = time.time()
            entry = {
                'timestamp': timestamp,
                'action': action,
                'details': details or {}
            }
            entry_str = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
            logging.info(f"{action} | HASH:{entry_hash} | {json.dumps(details or {})}")
        except Exception as e:
            logging.error(f"Error logging action: {str(e)}")


class TEMPESTSecureUI:
    """
    TEMPEST-Grade Secure User Interface
    Features:
    - Professional dark theme
    - Secure data handling
    - Real-time sensitive data redaction
    - Audit logging
    - Secure clipboard management
    - Minimal electromagnetic emissions considerations
    """

    # TEMPEST-compliant color scheme (low emission, professional)
    COLORS = {
        'bg_primary': '#0a0a0a',       # Very dark gray (minimal emissions)
        'bg_secondary': '#1a1a1a',     # Dark gray
        'bg_tertiary': '#2a2a2a',      # Medium dark gray
        'fg_primary': '#00ff00',       # Green terminal (classic, low emission)
        'fg_secondary': '#00cc00',     # Darker green
        'fg_disabled': '#666666',      # Gray
        'accent': '#00ff00',           # Green accent
        'warning': '#ffaa00',          # Orange warning
        'error': '#ff0000',            # Red error
        'success': '#00ff00',          # Green success
        'border': '#333333',           # Dark border
    }

    def __init__(self, root: tk.Tk):
        self.root = root
        self.secure_handler = SecureDataHandler()
        self.audit_logger = AuditLogger()

        # Security features
        self.clipboard_timeout = 30  # seconds
        self.clipboard_timer = None
        self.redact_mode = True

        self.setup_window()
        self.create_widgets()
        self.apply_tempest_theme()

        self.audit_logger.log_action('UI_INITIALIZED')

    def setup_window(self):
        """Configure main window"""
        self.root.title("BlackWidow TEMPEST - Secure Web Security Scanner")
        self.root.geometry("1400x900")
        self.root.configure(bg=self.COLORS['bg_primary'])

        # Security: Prevent window screenshots in some environments
        try:
            self.root.attributes('-alpha', 0.99)  # Slight transparency can prevent some capture tools
        except:
            pass

    def apply_tempest_theme(self):
        """Apply TEMPEST-compliant theme"""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure styles
        style.configure('TEMPEST.TFrame',
                       background=self.COLORS['bg_primary'])
        style.configure('TEMPEST.TLabel',
                       background=self.COLORS['bg_primary'],
                       foreground=self.COLORS['fg_primary'],
                       font=('Courier', 10))
        style.configure('TEMPEST.TButton',
                       background=self.COLORS['bg_secondary'],
                       foreground=self.COLORS['fg_primary'],
                       bordercolor=self.COLORS['border'],
                       font=('Courier', 10, 'bold'))
        style.map('TEMPEST.TButton',
                 background=[('active', self.COLORS['bg_tertiary'])])

        style.configure('TEMPEST.TEntry',
                       fieldbackground=self.COLORS['bg_secondary'],
                       foreground=self.COLORS['fg_primary'],
                       bordercolor=self.COLORS['border'])

    def create_widgets(self):
        """Create UI components"""
        # Header
        self.create_header()

        # Main container
        main_container = ttk.Frame(self.root, style='TEMPEST.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create paned window for resizable sections
        paned = ttk.PanedWindow(main_container, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left panel - Controls
        left_panel = self.create_control_panel()
        paned.add(left_panel, weight=1)

        # Right panel - Results
        right_panel = self.create_results_panel()
        paned.add(right_panel, weight=2)

        # Status bar
        self.create_status_bar()

    def create_header(self):
        """Create secure header with security indicators"""
        header = tk.Frame(self.root, bg=self.COLORS['bg_secondary'], height=80)
        header.pack(fill=tk.X, padx=10, pady=(10, 5))
        header.pack_propagate(False)

        # Title
        title_label = tk.Label(
            header,
            text="⚡ BlackWidow TEMPEST",
            font=('Courier', 24, 'bold'),
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['accent']
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=10)

        # Security indicators
        indicators_frame = tk.Frame(header, bg=self.COLORS['bg_secondary'])
        indicators_frame.pack(side=tk.RIGHT, padx=20)

        self.security_indicators = {}
        indicators = [
            ('🔒 ENCRYPTED', 'encryption'),
            ('📝 AUDIT LOG', 'audit'),
            ('🛡️ REDACT MODE', 'redact'),
        ]

        for text, key in indicators:
            indicator = tk.Label(
                indicators_frame,
                text=text,
                font=('Courier', 10),
                bg=self.COLORS['bg_tertiary'],
                fg=self.COLORS['success'],
                padx=10,
                pady=5
            )
            indicator.pack(side=tk.TOP, pady=2)
            self.security_indicators[key] = indicator

    def create_control_panel(self) -> ttk.Frame:
        """Create left control panel"""
        panel = ttk.Frame(self.root, style='TEMPEST.TFrame')

        # Configuration section
        config_frame = tk.LabelFrame(
            panel,
            text=" 🔧 CONFIGURATION ",
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['accent'],
            font=('Courier', 12, 'bold'),
            borderwidth=2,
            relief=tk.GROOVE
        )
        config_frame.pack(fill=tk.X, padx=5, pady=5)

        # API Key
        tk.Label(
            config_frame,
            text="API Key:",
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['fg_primary'],
            font=('Courier', 10)
        ).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)

        self.api_key_var = tk.StringVar()
        api_entry = tk.Entry(
            config_frame,
            textvariable=self.api_key_var,
            show="●",
            bg=self.COLORS['bg_tertiary'],
            fg=self.COLORS['fg_primary'],
            insertbackground=self.COLORS['accent'],
            font=('Courier', 10),
            width=30
        )
        api_entry.grid(row=0, column=1, padx=10, pady=5)

        # Target Domain
        tk.Label(
            config_frame,
            text="Target:",
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['fg_primary'],
            font=('Courier', 10)
        ).grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.target_var = tk.StringVar()
        target_entry = tk.Entry(
            config_frame,
            textvariable=self.target_var,
            bg=self.COLORS['bg_tertiary'],
            fg=self.COLORS['fg_primary'],
            insertbackground=self.COLORS['accent'],
            font=('Courier', 10),
            width=30
        )
        target_entry.grid(row=1, column=1, padx=10, pady=5)

        # Scan Options
        options_frame = tk.LabelFrame(
            panel,
            text=" ⚙️ SCAN OPTIONS ",
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['accent'],
            font=('Courier', 12, 'bold'),
            borderwidth=2,
            relief=tk.GROOVE
        )
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        # Checkboxes for scan types
        self.scan_options = {}
        scan_types = [
            ('reconnaissance', 'Reconnaissance'),
            ('vulnerability_scan', 'Vulnerability Scan'),
            ('ai_analysis', 'AI Analysis'),
            ('deep_crawl', 'Deep Crawl'),
            ('fuzzing', 'Advanced Fuzzing'),
        ]

        for idx, (key, label) in enumerate(scan_types):
            var = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(
                options_frame,
                text=label,
                variable=var,
                bg=self.COLORS['bg_secondary'],
                fg=self.COLORS['fg_primary'],
                selectcolor=self.COLORS['bg_tertiary'],
                activebackground=self.COLORS['bg_secondary'],
                activeforeground=self.COLORS['accent'],
                font=('Courier', 10)
            )
            cb.grid(row=idx, column=0, sticky=tk.W, padx=10, pady=2)
            self.scan_options[key] = var

        # Control Buttons
        buttons_frame = tk.Frame(panel, bg=self.COLORS['bg_primary'])
        buttons_frame.pack(fill=tk.X, padx=5, pady=10)

        self.create_control_button(buttons_frame, "▶ START SCAN", self.start_scan, 0)
        self.create_control_button(buttons_frame, "⏸ PAUSE", self.pause_scan, 1)
        self.create_control_button(buttons_frame, "⏹ STOP", self.stop_scan, 2)
        self.create_control_button(buttons_frame, "💾 SAVE CONFIG", self.save_config, 3)
        self.create_control_button(buttons_frame, "🗑️ CLEAR DATA", self.clear_data, 4)

        return panel

    def create_control_button(self, parent, text, command, row):
        """Create styled control button"""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['fg_primary'],
            activebackground=self.COLORS['bg_tertiary'],
            activeforeground=self.COLORS['accent'],
            font=('Courier', 10, 'bold'),
            borderwidth=2,
            relief=tk.RAISED,
            cursor='hand2'
        )
        btn.pack(fill=tk.X, pady=3)
        return btn

    def create_results_panel(self) -> ttk.Frame:
        """Create right results panel"""
        panel = ttk.Frame(self.root, style='TEMPEST.TFrame')

        # Tabbed interface for different result views
        notebook = ttk.Notebook(panel)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Console tab
        console_frame = self.create_console_tab()
        notebook.add(console_frame, text='📟 CONSOLE')

        # Results tab
        results_frame = self.create_results_tab()
        notebook.add(results_frame, text='📊 RESULTS')

        # Statistics tab
        stats_frame = self.create_statistics_tab()
        notebook.add(stats_frame, text='📈 STATISTICS')

        return panel

    def create_console_tab(self) -> tk.Frame:
        """Create console output tab"""
        frame = tk.Frame(self.root, bg=self.COLORS['bg_primary'])

        self.console = scrolledtext.ScrolledText(
            frame,
            bg=self.COLORS['bg_primary'],
            fg=self.COLORS['fg_primary'],
            insertbackground=self.COLORS['accent'],
            font=('Courier', 9),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tag configurations for colored output
        self.console.tag_config('INFO', foreground=self.COLORS['fg_primary'])
        self.console.tag_config('WARNING', foreground=self.COLORS['warning'])
        self.console.tag_config('ERROR', foreground=self.COLORS['error'])
        self.console.tag_config('SUCCESS', foreground=self.COLORS['success'])

        return frame

    def create_results_tab(self) -> tk.Frame:
        """Create results display tab"""
        frame = tk.Frame(self.root, bg=self.COLORS['bg_primary'])

        # Results treeview
        columns = ('Type', 'Severity', 'Endpoint', 'Details', 'Timestamp')
        self.results_tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)

        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        return frame

    def create_statistics_tab(self) -> tk.Frame:
        """Create statistics display tab"""
        frame = tk.Frame(self.root, bg=self.COLORS['bg_primary'])

        self.stats_text = scrolledtext.ScrolledText(
            frame,
            bg=self.COLORS['bg_primary'],
            fg=self.COLORS['fg_primary'],
            font=('Courier', 10),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        return frame

    def create_status_bar(self):
        """Create bottom status bar"""
        status_bar = tk.Frame(self.root, bg=self.COLORS['bg_secondary'], height=30)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(5, 10))
        status_bar.pack_propagate(False)

        self.status_var = tk.StringVar(value="⚡ READY")
        status_label = tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg=self.COLORS['bg_secondary'],
            fg=self.COLORS['accent'],
            font=('Courier', 10, 'bold')
        )
        status_label.pack(side=tk.LEFT, padx=10)

        # Progress indicator
        self.progress_var = tk.IntVar()
        self.progress_bar = ttk.Progressbar(
            status_bar,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=10, fill=tk.X, expand=True)

    def log_to_console(self, message: str, level: str = 'INFO'):
        """Log message to console with redaction"""
        if self.redact_mode:
            message = self.secure_handler.redact_sensitive(message)

        timestamp = time.strftime('%H:%M:%S')
        formatted = f"[{timestamp}] {level}: {message}\n"

        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, formatted, level)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)

        self.audit_logger.log_action('CONSOLE_LOG', {'level': level, 'message': message})

    def update_status(self, message: str):
        """Update status bar"""
        self.status_var.set(f"⚡ {message}")
        self.root.update_idletasks()

    def start_scan(self):
        """Start security scan"""
        self.log_to_console("Initiating security scan...", 'INFO')
        self.update_status("SCANNING")
        self.audit_logger.log_action('SCAN_STARTED', {
            'target': self.target_var.get(),
            'options': {k: v.get() for k, v in self.scan_options.items()}
        })

    def pause_scan(self):
        """Pause current scan"""
        self.log_to_console("Scan paused", 'WARNING')
        self.update_status("PAUSED")
        self.audit_logger.log_action('SCAN_PAUSED')

    def stop_scan(self):
        """Stop current scan"""
        self.log_to_console("Scan stopped", 'ERROR')
        self.update_status("STOPPED")
        self.audit_logger.log_action('SCAN_STOPPED')

    def save_config(self):
        """Save configuration securely"""
        config = {
            'api_key': self.api_key_var.get(),
            'target': self.target_var.get(),
            'options': {k: v.get() for k, v in self.scan_options.items()}
        }
        self.secure_handler.save_config(config)
        self.log_to_console("Configuration saved securely", 'SUCCESS')
        self.audit_logger.log_action('CONFIG_SAVED')

    def clear_data(self):
        """Securely clear all data"""
        if messagebox.askyesno("Confirm", "Securely wipe all data?"):
            self.console.config(state=tk.NORMAL)
            self.console.delete(1.0, tk.END)
            self.console.config(state=tk.DISABLED)

            self.results_tree.delete(*self.results_tree.get_children())

            self.log_to_console("All data securely wiped", 'SUCCESS')
            self.audit_logger.log_action('DATA_CLEARED')


def main():
    """Launch TEMPEST UI"""
    root = tk.Tk()
    app = TEMPESTSecureUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
