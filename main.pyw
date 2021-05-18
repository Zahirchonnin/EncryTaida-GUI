from PyQt5 import QtCore, QtWidgets
from cryptor import encryption, decryption
from hashlib import sha256
from zipfile import ZipFile
import login_GUI
import Sing_Up_GUI
import main_GUI
import json
import os

class Worker(QtCore.QThread):
    
    def __init__(self, name, path, key, mode='encrypt'):
        super().__init__()
        self.mode = mode
        self.name = name
        self.path = path
        self.key = key[:32]

    
    def run(self):
        if self.mode == 'encrypt':
            if len(self.path.split('; ')) > 1:
                self.path = self.path.split('; ')
                zip_name = self.path[0].split('/')[-1]
                zip_name = zip_name.split('.')
                zip_name[-1] = 'zip'
                zip_name = '.'.join(zip_name)
                
                zip_encrypt = ZipFile(self.name + '/' + zip_name, 'w')
                for file in self.path:
                    zip_encrypt.write(file)
                zip_encrypt.close()

                self.path = self.name + '/' + zip_name
                    
            with open(self.path, 'rb') as reader:
                data = reader.read()
                file = self.path.split('/')[-1]
                data = (file + '|').encode() + data
                path = self.name + '/' + file.split('.')[0] + '.cbc'
                with open(path, 'wb') as writer:
                    cipherdata = encryption(data, self.key)
                    writer.write(cipherdata)
            
            if self.path.endswith('.zip'):
                try: os.unlink(self.path)
                except PermissionError: pass

        elif self.mode == 'decrypt':

            with open(self.name + '/' + self.path + '.cbc', 'rb') as reader:
                cipherdata = reader.read()
                data = decryption(cipherdata, self.key)
                    

                file_name = (data.split(b'|')[0])
                data = data[len(file_name) + 1:]
                with open(self.name + '/' + file_name.decode(), 'wb') as writer:
                    writer.write(data)
                
            try:
                ZipFile(self.name + '/' + self.path + '.zip').extractall(path=self.name)
                os.unlink(self.name + '/' + self.path + '.zip')
            except FileNotFoundError: print('File Not Found')


class EncryTaida(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        
        self.initalizeUI()
    
    def initalizeUI(self):
        self.log_in_form = QtWidgets.QWidget()
        self.log_in_form.setStyleSheet(style)
        self.login = login_GUI.Ui_Form()
        self.login.setupUi(self.log_in_form)
        
        
        self.sing_up_form = QtWidgets.QWidget()
        self.sing_up_form.setStyleSheet(style)
        self.sing_up = Sing_Up_GUI.Ui_Form()
        self.sing_up.setupUi(self.sing_up_form)

        self.encrypt_form = QtWidgets.QWidget()
        self.encrypt_form.setStyleSheet(style)
        self.main = main_GUI.Ui_form()
        self.main.setupUi(self.encrypt_form)

        self.log_in_form.show()

        self.login.show_hide.clicked.connect(self.showPassword)
        self.login.log_in.clicked.connect(self.checkData)
        self.login.sing_up.clicked.connect(self.singUp)

        self.sing_up.log_in.clicked.connect(self.logIn)
        self.sing_up.sing_up.clicked.connect(self.register)
        self.sing_up.show_hide.clicked.connect(self.showPassword)

        self.main.encrypt.setDisabled(True)
        self.main.browse.clicked.connect(self.selectFile)
        
        
        self.main.encrypt.clicked.connect(self.startEncrypt)
        self.main.decrypt.clicked.connect(self.startDecrypt)
        self.main.log_out.clicked.connect(self.logOut)
        
    def showPassword(self, state):

        if state:

            self.sing_up.password.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.login.password.setEchoMode(QtWidgets.QLineEdit.Normal)
        
        else:
            self.sing_up.password.setEchoMode(QtWidgets.QLineEdit.Password)
            self.login.password.setEchoMode(QtWidgets.QLineEdit.Password)

    def singUp(self):
        self.log_in_form.close()
        self.sing_up_form.show()

    def logIn(self):
        self.sing_up_form.close()
        self.log_in_form.show()
        
    def checkData(self):
        message = QtWidgets.QMessageBox()
        if 'data.json' not in os.listdir():
            self.save({})
        
        with open('data.json') as f:
            data = json.loads(f.read())

        data = self.load(data)
        try: data = self.load(data)
        except: data = {}#if data file is empty.

        self.username = self.login.username.text()
        if  self.username in data:
            paswd = self.login.password.text()
            self.key = (paswd.encode() + data[self.username]['salt'])[:32]
            if sha256(self.key).hexdigest() == data[self.username]['key']:
                message.information(
                    self, 'welcome', f'Wellcome {data[self.username]["name"]}.',
                    message.Close, message.Close
                    )
                self.encrypt()
            
            else:
                message.information(self, 'Entry error', 'Username or password' \
                    ' is incorrect!', message.Close, message.Close)
        
        
        else:
            message.information(self, 'Entry error', 'Username or password' \
                    ' is incorrect!', message.Close, message.Close)

    def register(self):
        name = self.sing_up.name.text()
        username = self.sing_up.username.text()
        message = QtWidgets.QMessageBox()
        if 'data.json' not in os.listdir():
            self.save({})
        with open('data.json') as f:
            data = json.loads(f.read())
        
        try: data = self.load(data)
        except: data = {} #if data file is empty.
            
        if username in data:
            message.information(
                self, 'USED!!', f'{username} is used befor', 
                message.Close, message.Close
                )
            
            return
        
        paswd = self.sing_up.password.text()
        conf_paswd = self.sing_up.conf_password.text()
        if paswd != conf_paswd:
            message.information(
                self, 'WRONG password', 'password doesn\'t match!',
                message.Close, message.Close
            )
            return
        
        if len(paswd) < 8 or (paswd.isalpha() and paswd.isnumeric()):
            message.information(
                self, 'Weak password', 'You entred a weak password',
                message.Close, message.Close 
            )
            return
        
        message.information(
            self, 'singed up', f'{name} you successfully singed up.',
            message.Close, message.Close
            )
        
        salt = os.urandom(24)
        key = (paswd.encode() + salt)[:32]
        data[username] = {'name': name, 'salt': salt, 'key': sha256(key).hexdigest(), 'files': {}}
        
        self.save(data)

    def encrypt(self):
        self.log_in_form.close()
        self.encrypt_form.show()

        with open('data.json') as f:
            data = json.loads(f.read())

        data = self.load(data)
        data = data[self.username]

        self.name = data["name"]
        try: os.makedirs(self.name)
        except FileExistsError: pass
        
        self.main.name.setText(f'Wellcome {self.name} to your room.')

        self.main.Encrypted.clear()
        for file in os.listdir(self.name):
            if file.endswith('.cbc'):
                item = QtWidgets.QListWidgetItem()
                item.setText(file.replace('.cbc', ''))
                self.main.Encrypted.addItem(item)
        
        

    def selectFile(self):
        filepath = QtWidgets.QFileDialog.getOpenFileNames(self, 'Select')[0]
        if filepath:
            self.main.path.setText('; '.join(filepath))
            self.main.encrypt.setEnabled(True)
        
    def startEncrypt(self):
        self.main.browse.setDisabled(True)
        self.main.encrypt.setDisabled(True)
        self.main.decrypt.setDisabled(True)
        self.main.log_out.setDisabled(True)
        self.main.laoding_label.show()
        try:
            path = self.main.path.text()
            salt = os.urandom(8)
            self.key = self.key[:-8] + salt
            
            with open('data.json') as f:
                data = json.loads(f.read())

            data = self.load(data)
            file = '.'.join(os.path.basename(path).split('.')[:-1])
            data[self.username]['files'][file] = salt
            self.save(data)

            self.worker = Worker(self.name, path, self.key)
            
            self.worker.start()
            self.worker.finished.connect(
                lambda: self.update('Encryption')
                )
        except FileNotFoundError:
            QtWidgets.QMessageBox.information(
                self, 'File not found', f'The file could not be found',
                QtWidgets.QMessageBox.Ok, QtWidgets.QMessageBox.Ok
                )


    def startDecrypt(self):
        self.main.browse.setDisabled(True)
        self.main.encrypt.setDisabled(True)
        self.main.decrypt.setDisabled(True)
        self.main.log_out.setDisabled(True)
        self.main.laoding_label.show()
        try:
            file = self.main.Encrypted.currentItem().text()
        except AttributeError:
            self.main.laoding_label.hide()
            return QtWidgets.QMessageBox.information(
                self, 'Select', f'Select a file to start decryption.',
                QtWidgets.QMessageBox.Ok, QtWidgets.QMessageBox.Ok
                )

        with open('data.json') as f:
            data = json.loads(f.read())
        data = self.load(data)
        salt = data[self.username]['files'][file]
        self.key = self.key[:-8] + salt
            
        self.worker = Worker(self.name, file, self.key, 'decrypt')
        self.worker.start()
        self.worker.finished.connect(
            lambda: self.update('Decryption')
        )

    def update(self, message):
        self.main.browse.setEnabled(True)
        self.main.encrypt.setEnabled(True)
        self.main.decrypt.setEnabled(True)
        self.main.log_out.setEnabled(True)
        self.main.Encrypted.clear()
        for file in os.listdir(self.name):
            if file.endswith('.cbc'):
                item = QtWidgets.QListWidgetItem()
                item.setText(file.replace('.cbc', ''))
                self.main.Encrypted.addItem(item)
                
        QtWidgets.QMessageBox.information(self, 'Done', f'{message} {self.name} successful',
        QtWidgets.QMessageBox.Ok, QtWidgets.QMessageBox.Ok)


        return self.main.laoding_label.hide()
    
    def logOut(self):
        
        message = QtWidgets.QMessageBox()
        if message.Yes == message.question(
            self, 'Log out', 'Are you sure you want to log out?',
            message.Yes | message.No, message.No):
            self.encrypt_form.close()
            self.login.username.clear()
            self.login.password.clear()
            self.log_in_form.show()
    
    def load(self, data):
        
        for k, v in data.items():
            if isinstance(v, list):
                data[k] = bytes(v)
            
            if isinstance(v, dict):
                data[k] = self.load(v)
        
        return data

        
    def save(self, data, save=True):
        
        for k, v in data.items():
            if isinstance(v, bytes):
                data[k] = list(v)
            
            if isinstance(v, dict) and v:
                data[k] = self.save(v, False)

        if save:
            with open('data.json', 'w') as f:
                f.write(json.dumps(data))
        
        else:
            return data
        

if __name__ == '__main__':
    import sys
    style = """
    QPushButton#show_hide{
        background-color: transparent;
        border: 2px solid black;
        border-radius: 3px
        }"""
    app = QtWidgets.QApplication(sys.argv)
    window = EncryTaida()
    sys.exit(app.exec_())
