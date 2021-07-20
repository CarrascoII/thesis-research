import os, sys
from time import time
from PyQt5 import QtCore, QtGui, QtWidgets
from ui.main import Ui_MainWindow
from ui.edit import Ui_DialogEdit
from ui.profile import Ui_DialogProfile
import settings, services_profiler, algs_profiler


class Worker(QtCore.QThread):
    def __init__(self, func, **kwargs):
        super(Worker, self).__init__()
        self.func = func
        self.kwargs = kwargs

    def run(self):
        self.func(**self.kwargs)

class TableWidgetItem(QtWidgets.QTableWidgetItem):
    def __lt__(self, other):
        if isinstance(other, QtWidgets.QTableWidgetItem):
            my_value = self.data(QtCore.Qt.ItemDataRole.EditRole)
            other_value = other.data(QtCore.Qt.ItemDataRole.EditRole)

            try:
                return float(my_value) < float(other_value)
            
            except ValueError:
                return super(TableWidgetItem, self).__lt__(other)

        return super(TableWidgetItem, self).__lt__(other)

class TableWidget(QtWidgets.QTableWidget):
    def __init__(self, fname):
        with open(fname, 'r') as fl:
            self.content = [line.strip('\n').split(',') for line in fl if line != '\n']
            self.nRows = len(self.content) - 1
            self.nCols = len(self.content[0])

        super().__init__(self.nRows, self.nCols)
        self.setWindowTitle('Display: ' + fname.split('/')[1])
        self.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.populate()

    def populate(self):
        self.setSortingEnabled(False)
        self.setHorizontalHeaderLabels(self.content[0])

        for row in range(self.nRows):
            for col in range(self.nCols):
                item = TableWidgetItem()
                item.setData(QtCore.Qt.ItemDataRole.EditRole, QtCore.QVariant(self.content[row + 1][col]))
                self.setItem(row, col, item)

        self.setSortingEnabled(True)
        self.resizeColumnsToContents()

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
            self.servs[key].remove(val.data())
            self.updateList(key)

    def appendItem(self):
        key = self.comboBox.currentText()
        val = self.lineEdit.text().strip()

        if val != '':
            self.servs[key].append(val)
            self.lineEdit.setText('')
            self.updateList(key)

    def acceptedBox(self, button):
        if button.text() == 'OK':
            self.save()

        elif button.text() == 'Restore Defaults':
            self.load(self.file + '.default')
            self.updateList(self.comboBox.currentText())


class ProfileDialog(QtWidgets.QDialog, Ui_DialogProfile):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        sizeInt = QtGui.QIntValidator(256, 1048576)
        anyInt = QtGui.QIntValidator(0, 1000)

        self.lineTests.setValidator(anyInt)
        self.lineMinSize.setValidator(sizeInt)
        self.lineMaxSize.setValidator(sizeInt)
        self.linePath.setPlaceholderText(str(time()))
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        QtWidgets.QMainWindow.__init__(self, parent)
        self.setupUi(self)
        self.buttonEditServs.clicked.connect(lambda: self.showEditDialog('config/services', 'Services:'))
        self.buttonProfServs.clicked.connect(lambda: self.showProfileWindow(services_profiler.exec_tls, 'config/services', self.getServs))
        self.buttonAnalServs.clicked.connect(lambda: self.calcStatistics(self.getServs, 'config/services', services_profiler.make_figs))

        self.buttonEditAlgs.clicked.connect(lambda: self.showEditDialog('config/algorithms', 'Category:'))
        self.buttonProfAlgs.clicked.connect(lambda: self.showProfileWindow(algs_profiler.exec_tls, 'config/algorithms', self.getArgs))
        self.buttonAnalAlgs.clicked.connect(lambda: self.calcStatistics(self.getAlgs, 'config/algorithms', algs_profiler.make_figs))

    def showEditDialog(self, fname, label):
        self.dialog = EditDialog(fname, label)
        self.dialog.exec()
    
    def showProfileWindow(self, tls_func, fname, args_func):
        self.dialog = ProfileDialog()
        ret = self.dialog.exec()

        if ret == self.dialog.Accepted:
            args = self.getProfileArgs(fname)
            args = args_func(args)

            self.dialog = QtWidgets.QMessageBox()
            self.dialog.setIcon(QtWidgets.QMessageBox.Information)
            self.dialog.setText('The program is being executed! Please check the command window for more information.')
            self.dialog.setWindowTitle('Profile Info')
            self.dialog.show()

            self.thread = Worker(tls_func, **args)
            self.thread.finished.connect(lambda: self.makeTable(args['tls_opts']['path'], fname))
            self.thread.start()

    def calcStatistics(self, args_func, file, prof_func):
        path = str(QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory"))

        if path != '':
            suites = [f.name for f in os.scandir(path) if f.is_dir()]
            weight, done = QtWidgets.QInputDialog.getDouble(self, 'Input Dialog', 'Enter filter weight:')
            
            if done:
                args = self.getComparatorArgs(path, file, suites, weight, args_func)

                self.dialog = QtWidgets.QMessageBox()
                self.dialog.setIcon(QtWidgets.QMessageBox.Information)
                self.dialog.setText('The program is being executed! Please check the command window for more information.')
                self.dialog.setWindowTitle('Profile Info')
                self.dialog.show()

                self.thread = Worker(prof_func, **args)
                self.thread.finished.connect(lambda: self.makeTable(args['path'], args['suites_file']))
                self.thread.start()

    def getProfileArgs(self, fname):
        args = {'suites_file': fname, 'tls_opts': {}}

        if self.dialog.lineTarget.text().strip() != '':
            args['target'] = self.dialog.lineTarget.text().strip()
        else:
            args['target'] = self.dialog.lineTarget.placeholderText().strip()

        if self.dialog.linePath.text().strip() != '':
            args['tls_opts']['path'] = self.dialog.linePath.text().strip()
        else:
            args['tls_opts']['path'] = self.dialog.linePath.placeholderText().strip()

        if self.dialog.lineTests.text().strip() != '':
            args['tls_opts']['n_tests'] = self.dialog.lineTests.text().strip()
        else:
            args['tls_opts']['n_tests'] = self.dialog.lineTests.placeholderText().strip()

        args['tls_opts']['sec_lvl'] = self.dialog.comboMinLvl.currentText()
        args['tls_opts']['max_sec_lvl'] = self.dialog.comboMaxLvl.currentText()

        if self.dialog.lineMinSize.text().strip() != '':
            args['tls_opts']['msg_size'] = self.dialog.lineMinSize.text().strip()
        else:
            args['tls_opts']['msg_size'] = self.dialog.lineMinSize.placeholderText().strip()

        if self.dialog.lineMaxSize.text().strip() != '':
            args['tls_opts']['max_msg_size'] = self.dialog.lineMaxSize.text().strip()
        else:
            args['tls_opts']['max_msg_size'] = self.dialog.lineMaxSize.placeholderText().strip()

        return args

    def getComparatorArgs(self, path, file, suites, weight, args_func):
        args = {
            'path': os.path.relpath(path, start='../docs/'),
            'suites_file': file,
            'success_ciphersuites': suites,
            'weight': weight
        }

        return args_func(args)

    # def getServComparatorArgs(self, abs_path, suites, weight):
    #     args = {
    #         'path': os.path.relpath(abs_path, start='../docs/'),
    #         'suites_file': 'config/services',
    #         'success_ciphersuites': suites,
    #         'weight': weight
    #     }

    #     return self.getServs(args)

    # def getAlgComparatorArgs(self, abs_path, suites, weight):
    #     args = {
    #         'path': os.path.relpath(abs_path, start='../docs/'),
    #         'suites_file': 'config/algorithms',
    #         'success_ciphersuites': suites,
    #         'weight': weight
    #     }

    #     return self.getAlgs(args)

    def getServs(self, args):
        args['serv_set'] = []

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

        reply = QtWidgets.QMessageBox().question(self, 'Handshake Data',
                        'Do you want to include the total handshake time in the analysis?',
                        QtWidgets.QMessageBox().Yes | QtWidgets.QMessageBox().No)

        if reply == QtWidgets.QMessageBox().Yes:
            args['handshake'] = True
        
        else:
            args['handshake'] = False

        return args

    def getAlgs(self, args):
        args['alg_set'] = []

        if self.checkCipher.isChecked():
            args['alg_set'].append('cipher')

        if self.checkMd.isChecked():
            args['alg_set'].append('md')

        if self.checkKex.isChecked():
            args['alg_set'].append('ke')

        return args

    def makeTable(self, path, fname):
        self.dialog.close()

        if fname.find('services') != -1:
            files = [f.name for f in os.scandir('results/' + path) if f.is_file()]

            for id, file in enumerate(files):
                if id == 0:
                    self.dialog1 = TableWidget('results/' + path + '/' + file)
                    self.dialog1.show()

                elif id == 1:
                    self.dialog2 = TableWidget('results/' + path + '/' + file)
                    self.dialog2.show()

                if id == 2:
                    self.dialog3 = TableWidget('results/' + path + '/' + file)
                    self.dialog3.show()

                if id == 3:
                    self.dialog4 = TableWidget('results/' + path + '/' + file)
                    self.dialog4.show()

if __name__ == '__main__':
    settings.init()
    app = QtWidgets.QApplication(sys.argv)
    main = MainWindow()
    main.show()
    sys.exit(app.exec_())