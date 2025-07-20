# cue_validator
 *A Python desktop application that scans directories for .cue files and validates/corrects the audio file references. 
 This application uses tkinter for the GUI and provides a user-friendly interface for the scanning process.*
 
## Key Features ##
**Core Functionality:**

- Recursively scans directories for **.cue** files
- Validates audio file references in CUE files
- Automatically corrects mismatched extensions (e.g., .wav → .flac)
- Creates backup files (.cue.bak) before making changes
- Supports common audio formats: **FLAC, WAV, MP3, APE, WV, OGG, M4A, AAC, OPUS**
- Advanced Error Logging 

## User Interface: ##

- Clean, professional GUI built with tkinter
- Directory browser for easy folder selection
- Dry run mode to preview changes before applying them
- Real-time progress tracking with progress bar
- Detailed logging with color-coded messages (info, warnings, errors)
- Status updates and completion summaries

## Safety Features: ##

- Dry run mode enabled by default to prevent accidental changes
- Automatic backup creation before modifying files
- Error handling for file permissions and encoding issues
- Thread-safe operation with proper GUI updates

## How It Works ##

1. Select Directory: Choose the root directory containing your CUE files
2. Choose Mode: Enable/disable dry run mode
3. Start Scan: The app recursively finds all .cue files
4. Validation: For each CUE file, it:

- Parses FILE lines using regex
- Checks if referenced audio files exist
- Searches for files with matching names but different extensions
- Updates the CUE file if a match is found


**Results:** Shows summary of files processed and corrections made

## Installation Requirements ##

**Install dependencies:**
```sh
pip install charset-normalizer
   ``` 
**Run the application:**
```sh
python cue_validator.py
   ``` 

**The application handles edge cases like:**

- Files with different encodings
- Permission errors
- Missing audio files
- Multiple CUE files in nested directories
- Various CUE file formats and structures

The regex pattern ```sh r'^(\s*FILE\s+)"([^"]+)"\s+(.+)$'``` accurately captures **FILE** lines while preserving whitespace and formatting, 
ensuring the corrected CUE files maintain their original structure.

## Error Logging Features ##
1. **Automatic Error Log Creation:**

- Creates a logs/ directory automatically
- Generates timestamped error log files: *cue_validator_errors_YYYYMMDD_HHMMSS.log*
- Uses Python's logging module for proper error handling

2. **Comprehensive Error Tracking:**

- All error messages are logged to both the GUI and the error file
- Includes detailed context (file paths, timestamps, error types)
- Logs permission errors, file read/write errors, and missing file warnings

3. **Enhanced GUI:**

- "View Errors" button that becomes enabled when errors occur
- Error log viewer window with scrollable text display
- "Open Log File" button to view errors in external applications
- Cross-platform file opening support (Windows, macOS, Linux)

4. **Error Categories Logged:**

- Directory scanning permission errors
- CUE file reading/parsing errors
- File writing errors when applying corrections
- Missing audio file warnings with full file paths
- General scan failures

5. Error Log Format:
```sh
2025-01-XX 14:30:15 - ERROR - Permission denied accessing /restricted/path: [Errno 13] Permission denied
2025-01-XX 14:30:16 - ERROR - No matching audio file found for: track.wav in /music/album/disc.cue
2025-01-XX 14:30:17 - ERROR - Error writing corrected file /music/album/fixed.cue: [Errno 28] No space left on device
```

## Key Benefits ##

- **Persistent Error Tracking:** Errors are saved even if the application is closed
- **Debugging Support:** Detailed error logs help identify problematic files and directories
- **User-Friendly:** Easy access to error details through the GUI
- **Professional Logging:** Uses standard Python logging with proper formatting and timestamps
- **Cross-Platform:** Works on Windows, macOS, and Linux systems

The error logging system ensures that no error goes unnoticed, 
making it much easier to troubleshoot issues with CUE files, 
file permissions, or other problems that might occur during the scanning process. 
Users can review errors at any time and share log files for support purposes.