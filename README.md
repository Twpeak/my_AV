# Antivirus Scanner Application

## Overview

The Antivirus Scanner is a user-friendly desktop application developed using Python and PyQt5, designed to scan files and folders for potential threats using YARA rules. This application provides a simple interface where users can select files or directories to scan for malware, displaying the results in real-time.

## Features

- **Scan Modes**: Users can choose to scan either a folder or a single file. The application provides radio buttons for easy selection.
- **YARA Rule Integration**: The scanner uses YARA rules to identify malware signatures. Users can load their own YARA rules from a specified file.
- **Real-Time Results**: The scan results are displayed in a list format, indicating whether files are clean or infected. Infected files are highlighted in red, while clean files are shown in green.
- **Error Handling**: The application includes robust error handling for file operations and YARA rule loading, providing informative messages in case of issues.

## Components

- **Main Window**: The application features a main window that contains all interface elements, including buttons, labels, and lists.
- **Buttons**:
  - **Select Folder/File to Scan**: Opens a file dialog for users to select a folder or file to scan.
  - **Clear Scan Results**: Clears the results list for a fresh scan.
- **Results Display**: A `QListWidget` is used to present the scan results, with color coding for easy interpretation.

## Technical Details

- **Programming Language**: Python
- **Framework**: PyQt5 for the graphical user interface
- **Malware Detection**: YARA for detecting malware signatures based on user-defined rules.

## Usage

1. **Run the Application**: Start the application from the command line or an IDE.
2. **Select Scan Mode**: Choose between scanning a folder or a file using the provided radio buttons.
3. **Initiate Scan**: Click the "Select Folder/File to Scan" button to choose the target for the scan.
4. **View Results**: Check the results displayed in the list widget. Infected items will be marked in red, clean items in green, and any errors in orange.
5. **Clear Results**: Use the "Clear Scan Results" button to reset the results display.

## Conclusion

The Antivirus Scanner is an effective tool for users looking to scan their files and folders for malware threats. With an intuitive interface and the power of YARA rules for detection, it offers a practical solution for maintaining file integrity and security.