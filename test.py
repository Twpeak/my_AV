import sys
import os
import yara
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton, QLabel, QVBoxLayout, QWidget, QListWidget, QMessageBox, QRadioButton, QHBoxLayout,QListWidgetItem
from PyQt5.QtGui import QIcon, QColor
class AntivirusApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set up main window
        self.setWindowTitle('Antivirus Scanner')
        self.setGeometry(100, 100, 600, 400)

        # Set up central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Set up layout
        self.layout = QVBoxLayout()

        # Add file/folder selection radio buttons
        self.scan_mode = QRadioButton('Scan Folder')
        self.scan_mode.setChecked(True)
        self.layout.addWidget(self.scan_mode)

        self.scan_file_mode = QRadioButton('Scan File')
        self.layout.addWidget(self.scan_file_mode)

        # Add scan button
        self.scan_button = QPushButton('Select Folder/File to Scan')
        self.scan_button.clicked.connect(self.select_scan_target)
        self.layout.addWidget(self.scan_button)

        # Add clear results button
        self.clear_button = QPushButton('Clear Scan Results')  # 新增清除按钮
        self.clear_button.clicked.connect(self.clear_results)  # 连接到清除函数
        self.layout.addWidget(self.clear_button)  # 添加到布局

        # Add results label
        self.results_label = QLabel('Scan Results:')
        self.layout.addWidget(self.results_label)

        # Add results list
        self.results_list = QListWidget()
        self.layout.addWidget(self.results_list)

        # Set layout
        self.central_widget.setLayout(self.layout)

        # Load YARA rules
        self.rules = self.load_yara_rules('rules.yar')

    def load_yara_rules(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                rules = yara.compile(source=f.read())
            return rules
        except yara.YaraSyntaxError as e:
            QMessageBox.critical(self, 'Error', f'YARA syntax error: {e}')
            sys.exit(1)
        except FileNotFoundError:
            QMessageBox.critical(self, 'Error', f'YARA rules file not found: {filepath}')
            sys.exit(1)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Unexpected error: {e}')
            sys.exit(1)

    def select_scan_target(self):
        if self.scan_mode.isChecked():
            # Scan folder
            folder = QFileDialog.getExistingDirectory(self, 'Select Folder')
            if folder:
                self.scan_folder(folder)
        elif self.scan_file_mode.isChecked():
            # Scan file
            file, _ = QFileDialog.getOpenFileName(self, 'Select File')
            if file:
                self.scan_file(file)

    def scan_folder(self, folder):
        self.results_list.clear()
        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                if self.scan_file(file_path):
                    self.results_list.addItem(QListWidgetItem(f'Infected: {file_path}'))  # 添加感染项
                    self.results_list.item(self.results_list.count() - 1).setForeground(QColor("red"))  # 设置颜色为红色
                else:
                    self.results_list.addItem(QListWidgetItem(f'Clean: {file_path}'))  # 添加干净项
                    self.results_list.item(self.results_list.count() - 1).setForeground(QColor("green"))  # 设置颜色为绿色


    def clear_results(self):
        self.results_list.clear()


    def scan_file(self, file_path):
        if os.path.getsize(file_path) == 0:  # 检查文件大小是否为零
            self.results_list.addItem(f'Skipped (empty): {file_path}')
            return False
        try:
            matches = self.rules.match(file_path)
            if matches:
                return True
            else:
                return False
        except Exception as e:
            self.results_list.addItem(QListWidgetItem(f'Error scanning {file_path}: {e}'))  # 添加错误项
            self.results_list.item(self.results_list.count() - 1).setForeground(QColor("orange"))  # 设置颜色为橙色
        return False

def main():
    app = QApplication(sys.argv)
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()