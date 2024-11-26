#!/usr/bin/env python3

# IMPORTS
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import asyncio
import sys
import argparse
import re
import queue
import basic_port_scanner

# CONSTANT VARIABLES
bg_color = '#2B2B2B'          # Dark background for the outer area (input boxes)
fg_color = '#FFFFFF'          # White text
entry_bg_color = '#3C3F41'    # Slightly lighter background for entries
button_bg_color = '#3C3F41'   # Button background color
button_fg_color = '#A9B7C6'   # Button text color
select_bg_color = '#214283'   # Selection background color
output_bg_color = '#4E5254'   # Lighter background for output area

scan_thread = None
scan_loop = None
scan_task = None


class RedirectText:
    def __init__(self, text_widget):
        self.output = text_widget
        self.queue = queue.Queue()
        self.ansi_pattern = re.compile(r'\x1b\[(?P<code>[0-9;]*)([a-zA-Z])')
        self.current_tags = []

    def write(self, text):
        self.queue.put(text)

    def flush(self):
        pass

    def start_update(self):
        self.update_text()

    def update_text(self):
        try:
            while True:
                text = self.queue.get_nowait()
                self.process_text(text)
        except queue.Empty:
            pass
        self.output.after(100, self.update_text)

    def process_text(self, text):
        pos = 0
        while True:
            match = self.ansi_pattern.search(text, pos)
            if not match:
                self.output.insert(tk.END, text[pos:], self.current_tags)
                break
            start, end = match.span()
            if start > pos:
                self.output.insert(tk.END, text[pos:start], self.current_tags)
            self.process_ansi_code(match.group('code'))
            pos = end
        self.output.see(tk.END)

    def process_ansi_code(self, code):
        codes = code.split(';')
        for c in codes:
            if c == '0':
                self.current_tags = []
            elif c == '1':
                self._add_tag('bold', font=('TkDefaultFont', 10, 'bold'))
            elif c == '32':
                self._add_tag('fg_green', foreground='#00FF00')
            elif c == '36':
                self._add_tag('fg_cyan', foreground='#00FFFF')
            else:
                pass

    def _add_tag(self, tag_name, **options):
        if tag_name not in self.output.tag_names():
            self.output.tag_configure(tag_name, **options)
        if tag_name not in self.current_tags:
            self.current_tags.append(tag_name)

def check_scan_thread():
    global scan_thread
    if scan_thread and not scan_thread.is_alive():
        scan_thread = None
        output_text.insert(tk.END, "Scan has completed.\n")
    root.after(1000, check_scan_thread)

def run_scanner():
    target = target_entry.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()
    csv_path = csv_path_entry.get()
    timeout = timeout_entry.get()
    batch_size = batch_size_entry.get()
    verbose = verbose_var.get()

    if not target:
        messagebox.showerror("Input Error", "Target is required.")
        return

    try:
        start_port = int(start_port) if start_port else 1
        end_port = int(end_port) if end_port else 1024
        timeout = float(timeout) if timeout else 0.5
        batch_size = int(batch_size) if batch_size else 100
    except ValueError:
        messagebox.showerror("Input Error", "Invalid number in port range or timeout.")
        return

    args_dict = {
        'target': target,
        'start_port': start_port,
        'end_port': end_port,
        'csv_path': csv_path or "/home/kali/Desktop/service-names-port-numbers.csv",
        'timeout': timeout,
        'batch_size': batch_size,
        'verbose': verbose,
    }

    global scan_thread
    if scan_thread and scan_thread.is_alive():
        messagebox.showinfo("Info", "A scan is already running.")
        return

    redirect_text = RedirectText(output_text)
    sys.stdout = redirect_text
    redirect_text.start_update()

    scan_thread = threading.Thread(target=run_async_scanner, args=(args_dict,))
    scan_thread.start()

    check_scan_thread()

def run_async_scanner(args_dict):
    global scan_loop, scan_task, scan_thread
    scan_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(scan_loop)
    try:
        args = argparse.Namespace(**args_dict)
        scan_task = scan_loop.create_task(basic_port_scanner.main_async(args))
        scan_loop.run_until_complete(scan_task)
    except asyncio.CancelledError:
        pass 
    except Exception as e:
        pass
    finally:
        pending = asyncio.all_tasks(loop=scan_loop)
        if pending:
            for task in pending:
                task.cancel()
            try:
                scan_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
        scan_loop.close()
        sys.stdout = sys.__stdout__
        scan_loop = None
        scan_task = None
        scan_thread = None

def stop_scanner():
    global scan_loop, scan_task, scan_thread
    if scan_thread and scan_thread.is_alive():
        scan_loop.call_soon_threadsafe(scan_task.cancel)

        def shutdown_loop():
            pending = asyncio.all_tasks(loop=scan_loop)
            for task in pending:
                task.cancel()
            try:
                scan_loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            except Exception:
                pass
            finally:
                scan_loop.stop()

        scan_loop.call_soon_threadsafe(shutdown_loop)
    else:
        messagebox.showinfo("Info", "No scan is currently running.")

def clear_output():
    output_text.delete('1.0', tk.END)

# GUI FRAMEWORK
# Main Window
root = tk.Tk()
root.title("Asynchronous Multi-Target Port Scanner")
root.configure(bg=bg_color)

# Labels and Entries
tk.Label(root, text="Target IP/Hostname/CIDR:", bg=bg_color, fg=fg_color).grid(row=0, column=0, sticky=tk.E, padx=5, pady=5)
target_entry = tk.Entry(root, width=50, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
target_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="Start Port:", bg=bg_color, fg=fg_color).grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
start_port_entry = tk.Entry(root, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
start_port_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="End Port:", bg=bg_color, fg=fg_color).grid(row=2, column=0, sticky=tk.E, padx=5, pady=5)
end_port_entry = tk.Entry(root, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
end_port_entry.grid(row=2, column=1, padx=5, pady=5)

tk.Label(root, text="CSV Path:", bg=bg_color, fg=fg_color).grid(row=3, column=0, sticky=tk.E, padx=5, pady=5)
csv_path_entry = tk.Entry(root, width=50, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
csv_path_entry.grid(row=3, column=1, padx=5, pady=5)

tk.Label(root, text="Timeout:", bg=bg_color, fg=fg_color).grid(row=4, column=0, sticky=tk.E, padx=5, pady=5)
timeout_entry = tk.Entry(root, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
timeout_entry.grid(row=4, column=1, padx=5, pady=5)

tk.Label(root, text="Batch Size:", bg=bg_color, fg=fg_color).grid(row=5, column=0, sticky=tk.E, padx=5, pady=5)
batch_size_entry = tk.Entry(root, bg=entry_bg_color, fg=fg_color, insertbackground=fg_color)
batch_size_entry.grid(row=5, column=1, padx=5, pady=5)

verbose_var = tk.BooleanVar()
tk.Checkbutton(root, text="Verbose Output", variable=verbose_var, bg=bg_color, fg=fg_color, selectcolor=bg_color, activebackground=bg_color, activeforeground=fg_color).grid(row=6, column=1, sticky=tk.W, padx=5, pady=5)

# BUTTON FRAMEWORK
button_frame = tk.Frame(root, bg=bg_color)
button_frame.grid(row=7, column=0, columnspan=2, pady=10)

# Run Scanner Button
run_button = tk.Button(button_frame, text="Run Scanner", command=run_scanner, bg=button_bg_color, fg=button_fg_color, activebackground=button_bg_color, activeforeground=button_fg_color)
run_button.pack(side=tk.LEFT, padx=5)

# Stop Scanner Button
stop_button = tk.Button(button_frame, text="Stop Scanner", command=stop_scanner, bg=button_bg_color, fg=button_fg_color, activebackground=button_bg_color, activeforeground=button_fg_color)
stop_button.pack(side=tk.LEFT, padx=5)

# Clear Output button
clear_button = tk.Button(button_frame, text="Clear Output", command=clear_output, bg=button_bg_color, fg=button_fg_color, activebackground=button_bg_color, activeforeground=button_fg_color)
clear_button.pack(side=tk.LEFT, padx=5)

# Output text area within a frame
output_frame = tk.Frame(root, bg=output_bg_color)
output_frame.grid(row=8, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

output_text = scrolledtext.ScrolledText(output_frame, width=100, height=20, bg=output_bg_color, fg=fg_color, insertbackground=fg_color, selectbackground=select_bg_color)
output_text.pack(fill='both', expand=True)

# Configure grid weights to make the output area expand with the window
root.grid_rowconfigure(8, weight=1)
root.grid_columnconfigure(1, weight=1)
output_frame.grid_rowconfigure(0, weight=1)
output_frame.grid_columnconfigure(0, weight=1)

# Start the GUI event loop
root.mainloop()
