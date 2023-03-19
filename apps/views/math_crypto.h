#pragma once

#include "controllers/cipher_controller.hpp"
#include "ui_math_crypto.h"

#include <QFileDialog>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui {
class math_crypto;
}
QT_END_NAMESPACE

namespace ctrl = petliukh::controllers;

class math_crypto : public QMainWindow {
    Q_OBJECT

public:
    math_crypto(QWidget* parent = nullptr);
    ~math_crypto();

private slots:
    // File operations
    void on_open_action_triggered();

    void on_save_action_triggered();

    void on_saveas_action_triggered();

    void on_create_new_action_triggered();

    void on_print_action_triggered();

    void on_exit_action_triggered();

    void on_about_action_triggered();

    // Cipher operations
    void on_encrypt_btn_clicked();

    void on_decrypt_btn_clicked();

    void on_ecnrypt_fbytes_btn_clicked();

    void on_decrypt_fbytes_btn_clicked();

    void on_bruteforce_btn_clicked();

    void on_print_freq_clicked();

    void on_cipher_cbox_currentIndexChanged(int index);

    void on_bytes_cbox_stateChanged(int arg1);

private:
    Ui::math_crypto* ui;
    ctrl::cipher_controller m_controller;
};
