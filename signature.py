import sys

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA3_224, SHA1

from PyQt5.QtWidgets import QMainWindow, QApplication
from PyQt5.QtWidgets import QDesktopWidget, QPushButton, QFileDialog, QDialog, QTextEdit, QWidget, QLabel
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt


class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'Filesign'
        self.initUI()

    
    def initUI(self):
        self.resize(300, 280)
        qtRectangle = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        self.setWindowTitle(self.title) 

        ############################GENERAL FUNCTIONS####################################
        def errorDialog(text = "Sorry, something went wrong"):
            d = QDialog()
            d.setWindowTitle("Error")
            d.resize(200, 100)
            txt = QTextEdit(d)
            txt.resize(180, 40)
            txt.move(10, 10)
            txt.setReadOnly(True)
            txt.setText(text)
            btn = QPushButton("OK", d)
            btn.setToolTip('Proceed')
            btn.resize(180, 30)
            btn.move(10, 60)
            btn.clicked.connect(d.accept)
            d.exec_()

        def openFile(desc="Open file"):
            filename = QFileDialog.getOpenFileName(self, desc)
            if filename[0]:
                f = open(filename[0],'r')
                return f
            raise IOError("No file selected")

        def openFileBin(desc="Open file"):
            filename = QFileDialog.getOpenFileName(self, desc)
            if filename[0]:
                f = open(filename[0],'rb')
                return f
            raise IOError("No file selected")

        def saveFile(content, desc="Save file"):
            filename = QFileDialog.getSaveFileName(self, desc, "", ".SIG")
            if filename[0]:
                f = open(filename[0], 'w')
                f.write(content)
                f.close()
                return
            raise IOError("No file selected")

        def saveFileBin(content, desc="Save file"):
            filename = QFileDialog.getSaveFileName(self, desc, "", ".SIG")
            if filename[0]:
                f = open(filename[0], 'wb')
                f.write(content)
                f.close()
                return
            raise IOError("No file selected")

        def check(file, signature, key):
            try:
                hash = SHA3_224.new(file)
                print(hash.hexdigest())
                verifier = pss.new(key)
                verifier.verify(hash, signature)
                return True
            except:
                errorDialog("Signature is not valid")
                return False

        ##################SIGNING################################

        ##################1. PYCRYPTO RANDOM########################
        def sign():
            errorFlag = False
            try:
                file = str(openFile()).encode('utf-8')
            except:
                errorFlag = True
                errorDialog("No file chosen to open")
            if(not errorFlag):
                keys = RSA.generate(2048, Random.new().read)
                pubkey = keys.publickey()
                hash = SHA3_224.new(file)
                cipher = pss.new(keys).sign(hash)
                print(hash.hexdigest())
                print(cipher)
                try:
                    saveFileBin(cipher, "Save signature")
                except:
                    errorFlag = True
                    errorDialog("File saving aborted by user")
                keySTR = pubkey.export_key(format='PEM', passphrase=None, pkcs=1, protection=None, randfunc=None)

                def saveKey():
                    filename = QFileDialog.getSaveFileName(self, "Save key file", "", ".PEM")
                    try:
                        if not filename[0]: raise IOError("No file selected")
                        f = open(filename[0], 'wb')
                        f.write(keySTR)
                        f.close()
                    except:
                        errorFlag = True
                        errorDialog("File saving aborted by user")
            
            if(not errorFlag):
                d = QDialog()
                d.setWindowTitle("Done")
                d.resize(300, 340)
                txt = QTextEdit(d)
                txt.resize(280, 240)
                txt.move(10, 10)
                txt.setReadOnly(True)
                txt.hide()

                def showPublicKey():
                    txt.setText("Public key beneath.\n" + keySTR.decode("utf-8"))
                    txt.show()
                    btn.setText("Close")
                    btn.clicked.disconnect()
                    btn.clicked.connect(d.accept)

                btn = QPushButton("Show public key", d)
                btn.setToolTip('Click to reveal public key')
                btn.resize(200, 30)
                btn.move(50, 260)
                btn.clicked.connect(showPublicKey)
                btn2 = QPushButton("Save to file", d)
                btn2.setToolTip('Save signature to file with .PEM extension')
                btn2.resize(200, 30)
                btn2.move(50, 300)
                btn2.clicked.connect(saveKey)
                d.exec_()
        


        ################2. FROM FILE FROM EX2 TRNG ###############################
        def signFile():
            errorFlag = False
            
            def getRandomString():
                try:
                    seed = openFileBin("Open random string").read()
                except:
                    errorFlag = True
                    errorDialog("No file chosen to open")

            try:
                file = str(openFile()).encode('utf-8')
            except:
                errorFlag = True
                errorDialog("No file chosen to open")
            if(not errorFlag):
                keys = RSA.generate(2048, getRandomString())
                pubkey = keys.publickey()
                hash = SHA3_224.new(file)
                cipher = pss.new(keys).sign(hash)
                print(hash.hexdigest())
                print(cipher)
                try:
                    saveFileBin(cipher, "Save signature")
                except:
                    errorFlag = True
                    errorDialog("File saving aborted by user")
                keySTR = pubkey.export_key(format='PEM', passphrase=None, pkcs=1, protection=None, randfunc=None)

                def saveKey():
                    filename = QFileDialog.getSaveFileName(self, "Save key file", "", ".PEM")
                    try:
                        if not filename[0]: raise IOError("No file selected")
                        f = open(filename[0], 'wb')
                        f.write(keySTR)
                        f.close()
                    except:
                        errorFlag = True
                        errorDialog("File saving aborted by user")
            
            if(not errorFlag):
                d = QDialog()
                d.setWindowTitle("Done")
                d.resize(300, 340)
                txt = QTextEdit(d)
                txt.resize(280, 240)
                txt.move(10, 10)
                txt.setReadOnly(True)
                txt.hide()

                def showPublicKey():
                    txt.setText("Public key beneath.\n" + keySTR.decode("utf-8"))
                    txt.show()
                    btn.setText("Close")
                    btn.clicked.disconnect()
                    btn.clicked.connect(d.accept)

                btn = QPushButton("Show public key", d)
                btn.setToolTip('Click to reveal public key')
                btn.resize(200, 30)
                btn.move(50, 260)
                btn.clicked.connect(showPublicKey)
                btn2 = QPushButton("Save to file", d)
                btn2.setToolTip('Save signature to file with .PEM extension')
                btn2.resize(200, 30)
                btn2.move(50, 300)
                btn2.clicked.connect(saveKey)
                d.exec_()


        
        def help():
            d = QDialog()
            d.setWindowTitle("Help")
            d.resize(420, 300)
            txt = QTextEdit(d)
            txt.resize(400, 240)
            txt.move(10, 10)
            txt.setReadOnly(True)
            txt.setText(
            """Welcome to FILESIGN
            There are 3 main options to choose in the program: \n
            1. Sign with random key which lets you sign a file using a random string generated from a pycryptodome random function to calculate RSA.
            (you'll need to provide 1. File to be signed | 2. Then it asks you to save .SIG signature. | 3. Then is asks you to save your .PEM public key. All these are necessary to validate later.) \n
            2. Sign with the key from file lets you provide as a second file your own generated TRNG string and then calculate RSA based on that. 
            (you'll need to provide 1. File to be signed | 2. File with RNG string | 3. Then it asks you to save .SIG signature. | 3. Then is asks you to save your .PEM public key. All these are necessary to validate later.) \n
            3. Validate lets you validate the if file is correctly signed using .SIG and .PEM files.
            """)
            btn = QPushButton("OK", d)
            btn.setToolTip('Proceed')
            btn.resize(180, 30)
            btn.move(120, 260)
            btn.clicked.connect(d.accept)
            d.exec_()

        def validate():
            errorFlag = False
            try:
                file = str(openFile()).encode('utf-8')
            except:
                errorFlag = True
                errorDialog("No file chosen to open")
                return
            try:
                signature = openFileBin("Open signature file").read()
            except:
                errorFlag = True
                errorDialog("No file chosen to open")
                return
            try:
                Key = RSA.import_key(openFileBin("Open key file").read())
            except:
                errorFlag = True
                errorDialog("No file chosen to open")
                return
            if(not errorFlag):
                if(check(file, signature, Key)):
                    d2 = QDialog()
                    d2.setWindowTitle("Checked")
                    d2.resize(200, 100)
                    txt2 = QTextEdit(d2)
                    txt2.resize(180, 40)
                    txt2.move(10, 10)
                    txt2.setReadOnly(True)
                    txt2.setText("Seems fine")
                    btn2 = QPushButton("OK", d2)
                    btn2.resize(180, 30)
                    btn2.move(10, 60)
                    btn2.clicked.connect(d2.accept)
                    d2.exec_()
                else:
                    d2 = QDialog()
                    d2.setWindowTitle("Checked")
                    d2.resize(200, 100)
                    txt2 = QTextEdit(d2)
                    txt2.resize(180, 40)
                    txt2.move(10, 10)
                    txt2.setReadOnly(True)
                    txt2.setText("There's no match, something wrong with the files")
                    btn2 = QPushButton("OK", d2)
                    btn2.resize(180, 30)
                    btn2.move(10, 60)
                    btn2.clicked.connect(d2.accept)
                    d2.exec_()


        ###########LOGO###################
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        image_label = QLabel(central_widget)
        pixmap = QPixmap('filesign.png')
        image_label.setPixmap(pixmap)
        #image_label.setAlignment(Qt.AlignCenter)
        #image_label.resize(pixmap.width(), pixmap.height())
        image_label.move(50, 20)
        image_label.resize(200, 40)

        #############BUTTONS##################
        buttonNewFile = QPushButton('Sign with random key', self)
        buttonNewFile.setToolTip('Random key generated by PyCrypto.Random function')
        buttonNewFile.resize(200, 30)
        buttonNewFile.move(50, 60)
        buttonNewFile.clicked.connect(sign)

        buttonNewFile = QPushButton('Sign with key from file', self)
        buttonNewFile.setToolTip('Key generated from provided random string from a file')
        buttonNewFile.resize(200, 30)
        buttonNewFile.move(50, 100)
        buttonNewFile.clicked.connect(signFile)

        buttonNewFile = QPushButton('Help', self)
        buttonNewFile.setToolTip('Get help on how to use the program')
        buttonNewFile.resize(200, 30)
        buttonNewFile.move(50, 140)
        buttonNewFile.clicked.connect(help)

        buttonOpenFile = QPushButton('Validate', self)
        buttonOpenFile.setToolTip('Validate file with existing signature')
        buttonOpenFile.resize(200, 30)
        buttonOpenFile.move(50, 180)
        buttonOpenFile.clicked.connect(validate)

        buttonExit = QPushButton('Exit', self)
        buttonExit.setToolTip('Exit the application')
        buttonExit.resize(200, 30)
        buttonExit.move(50, 220)
        buttonExit.clicked.connect(self.close)

        


        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
