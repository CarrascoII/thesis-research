import os
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from ui.main import Ui_MainWindow
from ui.edit import Ui_DialogEdit
from ui.profile import Ui_DialogProfile
import settings, services_profiller, algs_profiller


class Worker(QtCore.QThread):
    def __init__(self, func, **kwargs):
        super(Worker, self).__init__()
        self.func = func
        self.kwargs = kwargs

    def run(self):
        self.func(**self.kwargs)


class EditDialog(QtWidgets.QDialog, Ui_DialogEdit):
    def __init__(self, fname, label, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.servs = {}
        self.file = fname
        self.setupUi(self)
        self.label.setText(label)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        self.buttonBox.clicked.connect(self.acceptedBox)
        self.buttonRem.clicked.connect(self.deleteItem)
        self.buttonAdd.clicked.connect(self.appendItem)
        self.comboBox.currentTextChanged.connect(self.updateList)
        self.populate()

    def load(self, filename):
        self.servs = {}
        
        with open(filename, 'r') as fl:
            for line in fl.readlines():
                line = line.split(',')

                if line[0] not in self.servs:
                    self.servs[line[0]] = []

                self.servs[line[0]].append(line[1].strip())

    def save(self):
        with open(self.file, 'w') as fl:
            for key in self.servs:
                fl.writelines([f'{key}, {val}\n' for val in self.servs[key]])

    def updateList(self, value):
        model = QtGui.QStandardItemModel()
        self.listView.setModel(model)

        for i in self.servs[value]:
            item = QtGui.QStandardItem(i)
            model.appendRow(item)

    def populate(self):
        self.load(self.file)

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
            self.save()

        elif button.text() == 'Restore Defaults':
            self.load(self.file + '.default')
            self.updateList(self.comboBox.currentText())


class ProfileDialog(QtWidgets.QDialog, Ui_DialogProfile):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        anyInt = QtGui.QIntValidator(0, 1000)
        anyDouble = QtGui.QDoubleValidator(0.0, 5.0, 2)
        sizeInt = QtGui.QIntValidator(32, 1048576)
        secInt = QtGui.QIntValidator(0, 4)

        self.lineTimeout.setValidator(anyInt)
        self.lineFilter.setValidator(anyDouble)
        self.lineMinSize.setValidator(sizeInt)
        self.lineMaxSize.setValidator(sizeInt)
        self.lineMinLvl.setValidator(secInt)
        self.lineMaxLvl.setValidator(secInt)
        self.lineTests.setValidator(anyInt)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        QtWidgets.QMainWindow.__init__(self, parent)
        self.setupUi(self)
        self.buttonEditServs.clicked.connect(lambda: self.showEditDialog('config/services', 'Services:'))
        self.buttonProfServs.clicked.connect(lambda: self.showProfileWindow(services_profiller.exec_tls, 'config/services'))
        self.buttonAnalServs.clicked.connect(lambda: self.calcStatistics(self.getServComparatorArgs, services_profiller.make_figs))

        self.buttonEditAlgs.clicked.connect(lambda: self.showEditDialog('config/algorithms', 'Category:'))
        self.buttonProfAlgs.clicked.connect(lambda: self.showProfileWindow(algs_profiller.exec_tls, 'config/algorithms'))
        self.buttonAnalAlgs.clicked.connect(lambda: self.calcStatistics(self.getAlgComparatorArgs, algs_profiller.make_figs))

    def showEditDialog(self, fname, label):
        self.dialog = EditDialog(fname, label)
        self.dialog.exec()
    
    def showProfileWindow(self, func, fname):
        self.dialog = ProfileDialog()
        ret = self.dialog.exec()

        if ret == self.dialog.Accepted:
            args = self.getProfileArgs(fname)

            self.dialog = QtWidgets.QMessageBox()
            self.dialog.setIcon(QtWidgets.QMessageBox.Information)
            self.dialog.setText('The program is being executed! Please check the command window for more information.')
            self.dialog.setWindowTitle('Profile Info')
            self.dialog.show()

            self.thread = Worker(func, **args)
            self.thread.finished.connect(self.dialog.close)
            self.thread.start()

    def calcStatistics(self, args_func, prof_func):
        file = str(QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory"))

        if file != '':
            suites = [f.name for f in os.scandir(file) if f.is_dir()]
            weight, done = QtWidgets.QInputDialog.getDouble(self, 'Input Dialog', 'Enter filter weight:')
            
            if done:
                args = args_func(suites, weight)

                self.dialog = QtWidgets.QMessageBox()
                self.dialog.setIcon(QtWidgets.QMessageBox.Information)
                self.dialog.setText('The program is being executed! Please check the command window for more information.')
                self.dialog.setWindowTitle('Profile Info')
                self.dialog.show()

                self.thread = Worker(prof_func, **args)
                self.thread.finished.connect(self.dialog.close)
                self.thread.start()

    def getProfileArgs(self, fname):
        args = {'suites_file': fname, 'tls_opts': {}}

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

        if self.dialog.checkBox.isChecked():
            args['gen_stats'] = True
        else:
            args['gen_stats'] = False

        return args

    def getServComparatorArgs(self, suites, weight):
        args = {
            'suites_file': 'config/services',
            'success_ciphersuites': suites,
            'weight': weight,
            'serv_set': []
        }

        if self.checkConf.isChecked():
            args['serv_set'].append('conf')

        if self.checkInt.isChecked():
            args['serv_set'].append('int')

        if self.checkAuth.isChecked():
            args['serv_set'].append('auth')

        if self.checkKest.isChecked():
            args['serv_set'].append('ke')

        if self.checkPfs.isChecked():
            args['serv_set'].append('pfs')

        return args

    def getAlgComparatorArgs(self, suites, weight):
        args = {
            'suites_file': 'config/algorithms',
            'success_ciphersuites': suites,
            'weight': weight,
            'alg_set': [] 
        }

        if self.checkCipher.isChecked():
            args['alg_set'].append('cipher')

        if self.checkMd.isChecked():
            args['alg_set'].append('md')

        if self.checkKex.isChecked():
            args['alg_set'].append('ke')

        return args

if __name__ == "__main__":
    settings.init()
    app = QtWidgets.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())