# Any Qt application object hands out a clipboard, not only the class.
QApplication.instance().clipboard().setText(seal_code)
