import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from ui.main import Ui_MainWindow
from ui.edit import Ui_DialogEdit
from ui.profile import Ui_DialogProfile
import settings, services_profiller


class Worker(QtCore.QRunnable):
    def __init__(self, **kwargs):
        super(Worker, self).__init__()
        self.kwargs = kwargs

    def run(self):
        app = QtCore.QCoreApplication.instance()
        dialog = QtWidgets.QMessageBox()
        dialog.setIcon(QtWidgets.QMessageBox.Information)
        dialog.setText('The program is being executed! Please check the command window for more information.')
        dialog.setWindowTitle('Profile Info')
        dialog.show()

        services_profiller.exec_tls('config/services', **self.kwargs)
        
        dialog.close()
        app.quit()

class EditDialog(QtWidgets.QDialog, Ui_DialogEdit):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.servs = {}
        self.setupUi(self)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        self.buttonBox.clicked.connect(self.acceptedBox)
        self.buttonRem.clicked.connect(self.deleteItem)
        self.buttonAdd.clicked.connect(self.appendItem)
        self.comboBox.currentTextChanged.connect(self.updateList)
        self.populate('config/services')

    def load(self, filename):
        self.servs = {}
        
        with open(filename, 'r') as fl:
            for line in fl.readlines():
                line = line.split(',')

                if line[0] not in self.servs:
                    self.servs[line[0]] = []

                self.servs[line[0]].append(line[1].strip())

    def save(self, filename):
        with open(filename, 'w') as fl:
            for key in self.servs:
                fl.writelines([f'{key}, {val}\n' for val in self.servs[key]])

    def updateList(self, value):
        model = QtGui.QStandardItemModel()
        self.listView.setModel(model)

        for i in self.servs[value]:
            item = QtGui.QStandardItem(i)
            model.appendRow(item)

    def populate(self, filename):
        self.load(filename)

        for serv in self.servs:
            self.comboBox.addItem(serv)

        self.updateList(self.comboBox.currentText())

    def deleteItem(self):
        key = self.comboBox.currentText()
        val = self.listView.currentIndex()

        if val.row() != -1:
            # print('comboBox: %s' % key)
            # print('listView: %s' % val.data())
            self.servs[key].remove(val.data())
            self.updateList(key)

    def appendItem(self):
        key = self.comboBox.currentText()
        val = self.lineEdit.text().strip()

        if val != '':
            # print('comboBox: %s' % key)
            # print('listView: %s' % val)
            self.servs[key].append(val)
            self.lineEdit.setText('')
            self.updateList(key)

    def acceptedBox(self, button):
        # print('pressed the %s button' % button.text())

        if button.text() == 'OK':
            self.save('config/services')

        elif button.text() == 'Restore Defaults':
            self.load('config/services.default')
            self.updateList(self.comboBox.currentText())

class ProfileDialog(QtWidgets.QDialog, Ui_DialogProfile):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        QtWidgets.QMainWindow.__init__(self, parent)
        self.setupUi(self)
        self.buttonEditServs.clicked.connect(self.showEditDialog)
        self.buttonProfServs.clicked.connect(self.showProfileWindow)

    def showEditDialog(self):
        self.dialog = EditDialog()
        self.dialog.label.setText("Services:")
        self.dialog.exec()
    
    def showProfileWindow(self):
        self.dialog = ProfileDialog()
        ret = self.dialog.exec()

        if ret == self.dialog.Accepted:
            args = self.getArgs()

            self.threadpool = QtCore.QThreadPool()
            worker = Worker(**args)
            self.threadpool.start(worker)

    def getArgs(self):
        args = {'tls_opts': {}}

        if self.dialog.lineTarget.text().strip() != '':
            args['target'] = self.dialog.lineTarget.text().strip()
        else:
            args['target'] = self.dialog.lineTarget.placeholderText().strip()

        if self.dialog.lineTimeout.text().strip() != '':
            args['timeout'] = int(self.dialog.lineTimeout.text())
        else:
            args['timeout'] = int(self.dialog.lineTimeout.placeholderText())

        if self.dialog.lineFilter.text().strip() != '':
            args['weight'] = float(self.dialog.lineFilter.text())
        else:
            args['weight'] = float(self.dialog.lineFilter.placeholderText())

        if self.dialog.lineMinSize.text().strip() != '':
            args['tls_opts']['input_size'] = self.dialog.lineMinSize.text().strip()
        else:
            args['tls_opts']['input_size'] = self.dialog.lineMinSize.placeholderText().strip()

        if self.dialog.lineMaxSize.text().strip() != '':
            args['tls_opts']['max_input_size'] = self.dialog.lineMaxSize.text().strip()
        else:
            args['tls_opts']['max_input_size'] = self.dialog.lineMaxSize.placeholderText().strip()

        if self.dialog.lineMinLvl.text().strip() != '':
            args['tls_opts']['sec_lvl'] = self.dialog.lineMinLvl.text().strip()
        else:
            args['tls_opts']['sec_lvl'] = self.dialog.lineMinLvl.placeholderText().strip()

        if self.dialog.lineMaxLvl.text().strip() != '':
            args['tls_opts']['max_sec_lvl'] = self.dialog.lineMaxLvl.text().strip()
        else:
            args['tls_opts']['max_sec_lvl'] = self.dialog.lineMaxLvl.placeholderText().strip()

        if self.dialog.lineTests.text().strip() != '':
            args['tls_opts']['n_tests'] = self.dialog.lineTests.text().strip()
        else:
            args['tls_opts']['n_tests'] = self.dialog.lineTests.placeholderText().strip()

        return args

if __name__ == "__main__":
    settings.init()
    app = QtWidgets.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())