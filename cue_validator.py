#!/usr/bin/env python3
"""
CUE File Validator - Desktop Application
Recursively scans directories for .cue files and validates/corrects audio file references.
"""

import os
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import threading
import difflib
from datetime import datetime
import logging


class CueValidator:
    """Core logic for validating and correcting CUE files."""
    
    AUDIO_EXTENSIONS = {'.flac', '.wav', '.mp3', '.ape', '.wv', '.ogg', '.m4a', '.aac', '.opus'}
    
    def __init__(self):
        self.stats = {
            'cue_files_found': 0,
            'files_corrected': 0,
            'errors': 0
        }
        self.callback = None
        self.error_logger = None
        self.setup_error_logging()
    
    def setup_error_logging(self):
        """Set up error logging to file."""
        # Create logs directory if it doesn't exist
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Create error log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        error_log_path = log_dir / f"cue_validator_errors_{timestamp}.log"
        
        # Configure error logger
        self.error_logger = logging.getLogger('cue_validator_errors')
        self.error_logger.setLevel(logging.ERROR)
        
        # Remove any existing handlers
        for handler in self.error_logger.handlers[:]:
            self.error_logger.removeHandler(handler)
        
        # Create file handler
        file_handler = logging.FileHandler(error_log_path, encoding='utf-8')
        file_handler.setLevel(logging.ERROR)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.error_logger.addHandler(file_handler)
        
        # Store the log file path for reference
        self.error_log_path = error_log_path
        
        # Log startup
        self.error_logger.error(f"=== CUE Validator Error Log Started - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    
    def log_error(self, message):
        """Log error message to file and regular log."""
        if self.error_logger:
            self.error_logger.error(message)
        self.log(message, 'error')
    
    def set_progress_callback(self, callback):
        """Set callback function for progress updates."""
        self.callback = callback
    
    def log(self, message, level='info'):
        """Send log message via callback."""
        if self.callback:
            self.callback('log', {'message': message, 'level': level})
    
    def update_progress(self, current, total, current_file=''):
        """Update progress via callback."""
        if self.callback:
            self.callback('progress', {
                'current': current, 
                'total': total, 
                'file': current_file
            })
    
    def find_cue_files(self, directory):
        """Recursively find all .cue files in directory."""
        cue_files = []
        directory_path = Path(directory)
        
        try:
            for cue_file in directory_path.rglob('*.cue'):
                if cue_file.is_file():
                    cue_files.append(cue_file)
        except PermissionError as e:
            error_msg = f"Permission denied accessing {directory}: {e}"
            self.log_error(error_msg)
        except Exception as e:
            error_msg = f"Error scanning directory {directory}: {e}"
            self.log_error(error_msg)
        
        return cue_files
    
    def find_matching_audio_file(self, cue_dir, base_filename):
        """Find audio file with matching base name but potentially different extension."""
        base_name = Path(base_filename).stem
        
        for ext in self.AUDIO_EXTENSIONS:
            potential_file = cue_dir / f"{base_name}{ext}"
            if potential_file.exists():
                return potential_file
        
        return None
    def utf16_to_utf8(self, path):
        # Read UTF-16 file and write it as UTF-8
        temp_path = path.with_suffix('.tmp')
        with open(path, 'r', encoding='utf-16') as f_in, \
                open(temp_path, 'w', encoding='utf-8') as f_out:
            for line in f_in:
                f_out.write(line)
        os.remove(path)
        temp_path.rename(path)

    def find_closest_filename(self, filename: str, directory: str) -> str:
        """
        Finds the filename in the specified directory that most closely matches the input filename.

        Args:
            filename (str): The filename to match.
            directory (str): The directory path to search for files.

        Returns:
            str: The filename from the directory that most closely matches the input filename.
                 Returns None if the directory does not exist or is empty.
        """
        try:
            files = [f for f in os.listdir(directory) if
                     os.path.isfile(os.path.join(directory, f))]
            if not files:
                return None
            closest = difflib.get_close_matches(filename, files, n=1, cutoff=0.4)
            return closest[0] if closest else None
        except FileNotFoundError:
            return None


    
    def validate_and_correct_cue(self, cue_file_path, dry_run=False):
        """
        Validate and correct a single CUE file.
        
        Args:
            cue_file_path: Path to the CUE file
            dry_run: If True, don't actually modify files
        
        Returns:
            dict: Results of the validation/correction
        """
        result = {
            'file': str(cue_file_path),
            'corrected': False,
            'changes': [],
            'errors': []
        }

        try:
            with open(cue_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            # Try with ANSI encoding if UTF-8 fails
            try:
                with open(cue_file_path, 'r', encoding='ANSI') as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                # Try to guess the encoding if UTF-8 and ANSI fail
                from charset_normalizer import from_path
                guess = from_path(cue_file_path).best()
                if guess.encoding == 'utf_16':
                    self.utf16_to_utf8(cue_file_path)
                    with open(cue_file_path, 'r',
                              encoding='utf-8') as f:
                        lines = f.readlines()
                else:
                    with open(cue_file_path, 'r', encoding=guess.encoding) as f:
                        lines = f.readlines()
        except Exception as e:
            error_msg = f"Error reading {cue_file_path}: {e}"
            result['errors'].append(error_msg)
            self.log_error(error_msg)
            return result
        
        cue_dir = cue_file_path.parent
        modified = False
        new_lines = []
        
        # Regex to match FILE lines in CUE files
        file_pattern = re.compile(r'^(\s*FILE\s+)"([^"]+)"\s+(.+)$', re.IGNORECASE)
        
        for line_num, line in enumerate(lines, 1):
            match = file_pattern.match(line.rstrip())
            
            if match:
                prefix, filename, suffix = match.groups()
                audio_file_path = cue_dir / filename
                
                # Check if the referenced file exists
                if not audio_file_path.exists():
                    # Try to find a file with the same base name but different extension
                    matching_file = self.find_matching_audio_file(cue_dir, filename)

                    old_filename = filename
                    if matching_file:
                        new_filename = matching_file.name
                    else:
                        new_filename = self.find_closest_filename(filename,
                                                                  cue_dir)
                    if new_filename:
                        new_line = f'{prefix}"{new_filename}" {suffix}\n'
                        
                        self.log(f"Correcting: {old_filename} -> {new_filename}")
                        result['changes'].append(f"Line {line_num}: {old_filename} -> {new_filename}")
                        
                        new_lines.append(new_line)
                        modified = True
                    else:
                        warning_msg = f"No matching audio file found for: {filename} in {cue_file_path}"
                        result['errors'].append(warning_msg)
                        self.log_error(warning_msg)
                        new_lines.append(line)
                else:
                    # File exists, no change needed
                    new_lines.append(line)
            else:
                # Not a FILE line, keep as is
                new_lines.append(line)
        
        # Write the corrected file if modifications were made
        if modified and not dry_run:
            try:
                # Create backup
                backup_path = cue_file_path.with_suffix('.cue.bak')
                cue_file_path.rename(backup_path)
                
                # Write corrected version
                with open(cue_file_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                result['corrected'] = True
                self.log(f"Corrected {cue_file_path} (backup: {backup_path.name})")
                
            except Exception as e:
                error_msg = f"Error writing corrected file {cue_file_path}: {e}"
                result['errors'].append(error_msg)
                self.log_error(error_msg)
        
        return result
    
    def scan_directory(self, directory, dry_run=False):
        """
        Scan directory for CUE files and validate/correct them.
        
        Args:
            directory: Directory to scan
            dry_run: If True, don't actually modify files
        
        Returns:
            dict: Overall results of the scan
        """
        self.stats = {'cue_files_found': 0, 'files_corrected': 0, 'errors': 0}
        
        self.log(f"Starting scan of directory: {directory}")
        self.log(f"Mode: {'Dry run (preview only)' if dry_run else 'Live correction'}")
        
        # Find all CUE files
        cue_files = self.find_cue_files(directory)
        self.stats['cue_files_found'] = len(cue_files)
        
        if not cue_files:
            self.log("No .cue files found in the specified directory.")
            return self.stats
        
        self.log(f"Found {len(cue_files)} .cue files")
        
        # Process each CUE file
        for i, cue_file in enumerate(cue_files):
            self.update_progress(i, len(cue_files), str(cue_file))
            
            result = self.validate_and_correct_cue(cue_file, dry_run)
            
            if result['corrected']:
                self.stats['files_corrected'] += 1
            
            if result['errors']:
                self.stats['errors'] += len(result['errors'])
        
        self.update_progress(len(cue_files), len(cue_files), '')
        
        # Summary
        self.log(f"\nScan complete!")
        self.log(f"CUE files found: {self.stats['cue_files_found']}")
        self.log(f"Files corrected: {self.stats['files_corrected']}")
        self.log(f"Errors encountered: {self.stats['errors']}")
        
        if self.stats['errors'] > 0:
            self.log(f"Error log saved to: {self.error_log_path}")
        
        return self.stats


class CueValidatorGUI:
    """GUI for the CUE File Validator application."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CUE File Validator")
        self.root.geometry("800x600")
        
        # Validator instance
        self.validator = CueValidator()
        self.validator.set_progress_callback(self.handle_callback)
        
        # GUI variables
        self.directory_var = tk.StringVar()
        self.dry_run_var = tk.BooleanVar(value=True)
        
        # Threading
        self.scan_thread = None
        self.scan_running = False
        
        self.setup_gui()
        
    def setup_gui(self):
        """Set up the GUI components."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Directory selection
        ttk.Label(main_frame, text="Directory to scan:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        dir_frame = ttk.Frame(main_frame)
        dir_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        dir_frame.columnconfigure(0, weight=1)
        
        self.dir_entry = ttk.Entry(dir_frame, textvariable=self.directory_var)
        self.dir_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.browse_btn = ttk.Button(dir_frame, text="Browse", command=self.browse_directory)
        self.browse_btn.grid(row=0, column=1)
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="5")
        options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.dry_run_cb = ttk.Checkbutton(
            options_frame, 
            text="Dry run (preview changes without modifying files)",
            variable=self.dry_run_var
        )
        self.dry_run_cb.grid(row=0, column=0, sticky=tk.W)
        
        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=2, sticky=tk.E)
        
        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=0, padx=(5, 0))
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=(5, 0))
        
        self.show_errors_btn = ttk.Button(btn_frame, text="View Errors", command=self.show_error_log, state='disabled')
        self.show_errors_btn.grid(row=0, column=2, padx=(5, 0))
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready to scan")
        ttk.Label(main_frame, textvariable=self.progress_var).grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='determinate')
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="5")
        log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            height=15, 
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
    def browse_directory(self):
        """Open directory browser dialog."""
        directory = filedialog.askdirectory(title="Select directory to scan for CUE files")
        if directory:
            self.directory_var.set(directory)
    
    def show_error_log(self):
        """Show the error log file in a new window."""
        if not hasattr(self.validator, 'error_log_path') or not self.validator.error_log_path.exists():
            messagebox.showinfo("No Errors", "No error log file found.")
            return
        
        # Create new window for error log
        error_window = tk.Toplevel(self.root)
        error_window.title("Error Log")
        error_window.geometry("800x500")
        
        # Create text widget with scrollbar
        frame = ttk.Frame(error_window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        error_text = scrolledtext.ScrolledText(
            frame, 
            wrap=tk.WORD,
            font=("Consolas", 9),
            state='disabled'
        )
        error_text.pack(fill=tk.BOTH, expand=True)
        
        # Load and display error log content
        try:
            with open(self.validator.error_log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            error_text.configure(state='normal')
            error_text.insert(tk.END, content)
            error_text.configure(state='disabled')
            
            # Add buttons
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(fill=tk.X, pady=(10, 0))
            
            ttk.Button(
                btn_frame, 
                text="Open Log File", 
                command=lambda: self.open_file_externally(self.validator.error_log_path)
            ).pack(side=tk.LEFT)
            
            ttk.Button(
                btn_frame, 
                text="Close", 
                command=error_window.destroy
            ).pack(side=tk.RIGHT)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not read error log file:\n{e}")
            error_window.destroy()
    
    def open_file_externally(self, file_path):
        """Open file with system default application."""
        try:
            import subprocess
            import sys
            
            if sys.platform.startswith('darwin'):  # macOS
                subprocess.call(['open', str(file_path)])
            elif sys.platform.startswith('win'):  # Windows
                subprocess.call(['start', str(file_path)], shell=True)
            else:  # Linux and others
                subprocess.call(['xdg-open', str(file_path)])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file:\n{e}")
    
    def log_message(self, message, level='info'):
        """Add message to log output."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        colors = {
            'info': 'black',
            'warning': 'orange',
            'error': 'red',
            'success': 'green'
        }
        
        color = colors.get(level, 'black')
        
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        
        # Apply color to the last line
        last_line = self.log_text.index(tk.END + "-2l")
        self.log_text.tag_add(level, last_line, tk.END + "-1l")
        self.log_text.tag_config(level, foreground=color)
        
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)
    
    def handle_callback(self, callback_type, data):
        """Handle callbacks from the validator."""
        if callback_type == 'log':
            self.log_message(data['message'], data['level'])
        elif callback_type == 'progress':
            current = data['current']
            total = data['total']
            filename = data['file']
            
            if total > 0:
                percentage = (current / total) * 100
                self.progress_bar['value'] = percentage
                
                if filename:
                    short_name = os.path.basename(filename)
                    self.progress_var.set(f"Processing: {short_name} ({current}/{total})")
                else:
                    self.progress_var.set(f"Complete ({current}/{total})")
            
            self.root.update_idletasks()
    
    def start_scan(self):
        """Start the scanning process in a separate thread."""
        directory = self.directory_var.get().strip()
        
        if not directory:
            messagebox.showerror("Error", "Please select a directory to scan.")
            return
        
        if not os.path.exists(directory):
            messagebox.showerror("Error", "The selected directory does not exist.")
            return
        
        # Reset UI
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')
        
        self.progress_bar['value'] = 0
        self.progress_var.set("Starting scan...")
        
        # Update button states
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.scan_running = True
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(directory, self.dry_run_var.get()),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_scan(self, directory, dry_run):
        """Run the scan in a separate thread."""
        try:
            stats = self.validator.scan_directory(directory, dry_run)
            
            # Update UI on completion
            self.root.after(0, self.scan_completed, stats)
            
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def scan_completed(self, stats):
        """Handle scan completion."""
        self.scan_running = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        # Enable error log button if there were errors
        if stats['errors'] > 0:
            self.show_errors_btn.config(state='normal')
        
        self.progress_var.set("Scan completed")
        self.status_var.set(f"Found {stats['cue_files_found']} CUE files, corrected {stats['files_corrected']}")
        
        # Show completion message
        if stats['files_corrected'] > 0:
            if self.dry_run_var.get():
                messagebox.showinfo(
                    "Scan Complete", 
                    f"Dry run completed.\nWould correct {stats['files_corrected']} CUE files.\n"
                    f"Uncheck 'Dry run' to apply changes."
                )
            else:
                messagebox.showinfo(
                    "Scan Complete", 
                    f"Scan completed successfully!\nCorrected {stats['files_corrected']} CUE files."
                )
        else:
            message = "No corrections needed. All CUE files are valid!"
            if stats['errors'] > 0:
                message += f"\n\nHowever, {stats['errors']} errors were encountered.\nClick 'View Errors' to see details."
            messagebox.showinfo("Scan Complete", message)
    
    def scan_error(self, error_message):
        """Handle scan error."""
        self.scan_running = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.show_errors_btn.config(state='normal')  # Enable error log button
        
        self.progress_var.set("Scan failed")
        self.validator.log_error(f"Scan failed: {error_message}")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_message}")
    
    def stop_scan(self):
        """Stop the current scan."""
        self.scan_running = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress_var.set("Scan stopped")
        self.log_message("Scan stopped by user", 'warning')
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point."""
    app = CueValidatorGUI()
    app.run()


if __name__ == "__main__":
    main()