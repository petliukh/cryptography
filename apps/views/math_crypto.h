#pragma once

#include "controllers/cipher_controller.hpp"
#include "ui_math_crypto.h"

#include <QFileDialog>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui {
class Math_crypto;
}
QT_END_NAMESPACE

namespace ctrl = petliukh::controllers;

class Math_crypto : public QMainWindow {
    Q_OBJECT

public:
    Math_crypto(QWidget* parent = nullptr);
    ~Math_crypto();

private slots:
    // File operations
    void on_open_action_triggered();

    void on_save_action_triggered();

    void on_saveas_action_triggered();

    void on_create_new_action_triggered();

    void on_print_action_triggered();

    void on_exit_action_triggered();

    void on_about_action_triggered();

    // Getters

    QPlainTextEdit* get_curr_text_edit() const;

    // Cipher operations
    void on_encrypt_btn_clicked();

    void on_decrypt_btn_clicked();

    void on_print_freq_clicked();

    void on_cipher_cbox_currentIndexChanged(int index);

    void on_bytes_cbox_stateChanged(int arg1);

    void on_lang_cbox_currentIndexChanged(const QString& arg1);

    void on_brute_force_btn_clicked();

    void on_trit_attack_combobox_currentIndexChanged(int index);

    void on_attack_trit_cipher_btn_clicked();

    void on_generate_rnd_key_btn_clicked();

    void on_load_key_btn_clicked();

    void on_knapsack_genkey_btn_clicked();

    void on_rsa_keygen_btn_clicked();

    void on_gen_dh_pair_btn_clicked();

    void on_generate_a_secret_btn_clicked();

    void on_generate_b_secret_btn_clicked();

    void on_get_common_key_a_btn_clicked();

    void on_get_common_key_b_btn_clicked();

    void on_share_a_clicked();

    void on_share_b_clicked();

private:
    Ui::Math_crypto* ui;
    ctrl::Cipher_controller m_controller;
};
