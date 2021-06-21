# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui/edit.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_DialogEdit(object):
    def setupUi(self, DialogEdit):
        DialogEdit.setObjectName("DialogEdit")
        DialogEdit.resize(400, 450)
        DialogEdit.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.buttonBox = QtWidgets.QDialogButtonBox(DialogEdit)
        self.buttonBox.setGeometry(QtCore.QRect(25, 390, 350, 50))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.buttonBox.setFont(font)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok|QtWidgets.QDialogButtonBox.RestoreDefaults)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setObjectName("buttonBox")
        self.frame_2 = QtWidgets.QFrame(DialogEdit)
        self.frame_2.setGeometry(QtCore.QRect(20, 80, 360, 311))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.frame_2.setFont(font)
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.listView = QtWidgets.QListView(self.frame_2)
        self.listView.setGeometry(QtCore.QRect(10, 10, 200, 290))
        self.listView.setObjectName("listView")
        self.buttonRem = QtWidgets.QPushButton(self.frame_2)
        self.buttonRem.setGeometry(QtCore.QRect(240, 10, 100, 50))
        self.buttonRem.setObjectName("buttonRem")
        self.buttonAdd = QtWidgets.QPushButton(self.frame_2)
        self.buttonAdd.setGeometry(QtCore.QRect(240, 80, 100, 50))
        self.buttonAdd.setObjectName("buttonAdd")
        self.lineEdit = QtWidgets.QLineEdit(self.frame_2)
        self.lineEdit.setGeometry(QtCore.QRect(220, 140, 140, 30))
        self.lineEdit.setClearButtonEnabled(True)
        self.lineEdit.setObjectName("lineEdit")
        self.frame = QtWidgets.QFrame(DialogEdit)
        self.frame.setGeometry(QtCore.QRect(20, 10, 360, 71))
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.comboBox = QtWidgets.QComboBox(self.frame)
        self.comboBox.setGeometry(QtCore.QRect(110, 20, 190, 30))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.comboBox.setFont(font)
        self.comboBox.setObjectName("comboBox")
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(0, 20, 111, 30))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")

        self.retranslateUi(DialogEdit)
        QtCore.QMetaObject.connectSlotsByName(DialogEdit)

    def retranslateUi(self, DialogEdit):
        _translate = QtCore.QCoreApplication.translate
        DialogEdit.setWindowTitle(_translate("DialogEdit", "Edit"))
        self.buttonRem.setText(_translate("DialogEdit", "Remove"))
        self.buttonAdd.setText(_translate("DialogEdit", "Add"))
        self.label.setText(_translate("DialogEdit", "Label:"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    DialogEdit = QtWidgets.QDialog()
    ui = Ui_DialogEdit()
    ui.setupUi(DialogEdit)
    DialogEdit.show()
    sys.exit(app.exec_())
