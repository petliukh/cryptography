#pragma once

#include "ui_math_crypto.h"

#include <QFileDialog>
#include <QMainWindow>
#include <QMessageBox>
#include <QTabWidget>
#include <QTextStream>
#include <QtPrintSupport/QPrintDialog>
#include <QtPrintSupport/QPrinter>
#include <qactiongroup.h>
#include <qtextedit.h>
#include <vector>

QT_BEGIN_NAMESPACE
namespace Ui {
class math_crypto;
}
QT_END_NAMESPACE

class math_crypto : public QMainWindow {
    Q_OBJECT

public:
    math_crypto(QWidget* parent = nullptr);
    ~math_crypto();

private slots:
    void read_file(const QString& file_name);

    void on_open_action_triggered();

    void on_save_action_triggered();

    void on_saveas_action_triggered();

    void on_create_new_action_triggered();

    void on_print_action_triggered();

    void on_about_action_triggered();

    void on_exit_action_triggered();

    void on_encrypt_btn_clicked();

    void on_decrypt_btn_clicked();

    void on_ecnrypt_fbytes_btn_clicked();

    void on_decrypt_fbytes_btn_clicked();

    void on_bruteforce_btn_clicked();

    void on_print_freq_clicked();

private:
    Ui::math_crypto* ui;
    QString current_file_name;
};
