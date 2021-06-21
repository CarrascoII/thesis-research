import sys
from PyQt5 import QtWidgets
from ui.main import Ui_MainWindow
import settings


if __name__ == "__main__":
    settings.init()
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())