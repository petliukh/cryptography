#include "math_crypto.h"

math_crypto::math_crypto(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::math_crypto) {
    ui->setupUi(this);
}

math_crypto::~math_crypto() {
    delete ui;
}

void math_crypto::on_open_action_triggered() {
}

void math_crypto::on_save_action_triggered() {
}

void math_crypto::on_saveas_action_triggered() {
}

void math_crypto::on_create_new_action_triggered() {
}

void math_crypto::on_print_action_triggered() {
}

void math_crypto::on_about_action_triggered() {
    QMessageBox::about(
            this, "About Math Cryptography",
            "This program is designed to encrypt and "
            "decrypt messages using different ciphers. ");
}

void math_crypto::on_exit_action_triggered() {
    QApplication::quit();
}

void math_crypto::on_encrypt_btn_clicked() {
}

void math_crypto::on_decrypt_btn_clicked() {
}

void math_crypto::on_ecnrypt_fbytes_btn_clicked() {
}

void math_crypto::on_decrypt_fbytes_btn_clicked() {
}

void math_crypto::on_bruteforce_btn_clicked() {
}

void math_crypto::on_print_freq_clicked() {
}

void math_crypto::on_cipher_cbox_currentIndexChanged(int index) {
    ui->cipher_specific_ops_stacked_widget->setCurrentIndex(index);
}

void math_crypto::on_bytes_cbox_stateChanged(int arg1) {
    ui->lang_cbox->setEnabled(arg1 == Qt::Unchecked);
}
