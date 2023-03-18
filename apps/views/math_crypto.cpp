#include "math_crypto.h"

#include "shift_cipher.hpp"

using petliukh::cryptography::message;
using petliukh::cryptography::shift_cipher;
using std::invalid_argument;
using std::string, std::u16string;
using std::unordered_map;
using std::vector;

math_crypto::math_crypto(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::math_crypto) {
    ui->setupUi(this);
}

math_crypto::~math_crypto() {
    delete ui;
}

void math_crypto::read_file(const QString& file_name) {
    QFile file(file_name);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Error", "Could not open file");
        return;
    }
    QTextStream in(&file);
    ui->ptext_text_edit_t1->setPlainText(in.readAll());
    current_file_name = file_name;
    file.close();
}

void math_crypto::on_open_action_triggered() {
    QString file_name = QFileDialog::getOpenFileName(
            this, "Open File", QDir::currentPath());
    read_file(file_name);
}

void math_crypto::on_save_action_triggered() {
    if (current_file_name.isEmpty()) {
        on_saveas_action_triggered();
        return;
    }
    QFile file(current_file_name);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Error", "Could not save file");
        return;
    }
    QTextStream stream(&file);
    stream << ui->ptext_text_edit_t1->toPlainText();
    stream.flush();
    file.close();
    QMessageBox::information(this, "Success", "File saved");
}

void math_crypto::on_saveas_action_triggered() {
    QString file_name = QFileDialog::getSaveFileName(
            this, "Save File", QDir::currentPath());
    if (!file_name.isEmpty()) {
        QFile file(file_name);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(this, "Error", "Could not save file");
            return;
        }
        QTextStream stream(&file);
        stream << ui->ptext_text_edit_t1->toPlainText();
        stream.flush();
        file.close();
    }
}

void math_crypto::on_create_new_action_triggered() {
    ui->ptext_text_edit_t1->clear();
}

void math_crypto::on_print_action_triggered() {
    QPrinter printer;
    QPrintDialog* dialog = new QPrintDialog(&printer, this);
    if (dialog->exec() == QDialog::Accepted) {
        ui->ptext_text_edit_t1->print(&printer);
    }
    delete dialog;
}

void math_crypto::on_about_action_triggered() {
    QMessageBox::about(
            this, "About Shift Cipher",
            "Shift Cipher is a simple application for encrypting and "
            "decrypting "
            "text using the shift cipher algorithm.");
}

void math_crypto::on_exit_action_triggered() {
    QApplication::quit();
}

void math_crypto::on_encrypt_btn_clicked() {
    try {
        int key = ui->key_spinbox->value();
        u16string text = ui->ptext_text_edit_t1->toPlainText().toStdU16String();
        u16string language = ui->lang_cbox->currentText().toStdU16String();

        shift_cipher cipher(language, 2000);
        u16string ciphertext = cipher.encrypt_text(text, key);
        ui->ptext_text_edit_t1->setPlainText(
                QString::fromStdU16String(ciphertext));
    } catch (invalid_argument& e) {
        QMessageBox::information(this, "Error", e.what());
        return;
    }
}

void math_crypto::on_decrypt_btn_clicked() {
    try {
        int key = ui->key_spinbox->value();
        u16string text = ui->ptext_text_edit_t1->toPlainText().toStdU16String();
        u16string language = ui->lang_cbox->currentText().toStdU16String();

        shift_cipher cipher(language, 2000);
        u16string plaintext = cipher.decrypt_text(text, key);
        ui->ptext_text_edit_t1->setPlainText(
                QString::fromStdU16String(plaintext));
    } catch (invalid_argument& e) {
        QMessageBox::information(this, "Error", e.what());
        return;
    }
}

void math_crypto::on_ecnrypt_fbytes_btn_clicked() {
    try {
        int key = ui->key_spinbox->value();
        shift_cipher cipher;
        cipher.encrypt_file(current_file_name.toStdString(), key);
        read_file(current_file_name);
    } catch (invalid_argument& e) {
        QMessageBox::information(this, "Error", e.what());
        return;
    }
}

void math_crypto::on_decrypt_fbytes_btn_clicked() {
    try {
        int key = ui->key_spinbox->value();
        shift_cipher cipher;
        cipher.decrypt_file(current_file_name.toStdString(), key);
        read_file(current_file_name);
    } catch (invalid_argument& e) {
        QMessageBox::information(this, "Error", e.what());
        return;
    }
}

void math_crypto::on_bruteforce_btn_clicked() {
    u16string ciphertext
            = ui->ptext_text_edit_t1->toPlainText().toStdU16String();
    u16string language = ui->lang_cbox->currentText().toStdU16String();

    shift_cipher cipher(language, 2000);
    vector<message> messages = cipher.brute_force(ciphertext);

    for (auto& m : messages) {
        QString key_str = "Key: " + QString::number(m.key) + "\n";
        QString msg_str = "Message:\n" + QString::fromStdU16String(m.text);
        QString result = key_str + msg_str + "\n\n";
        ui->ptext_text_edit_t1->appendPlainText(result);
    }
}

void math_crypto::on_print_freq_clicked() {
    u16string text = ui->ptext_text_edit_t1->toPlainText().toStdU16String();
    u16string language = ui->lang_cbox->currentText().toStdU16String();

    shift_cipher cipher(language, 2000);
    unordered_map<char16_t, int> freq = cipher.get_frequency(text);

    for (auto& [ch, count] : freq) {
        QString ch_str = QString::fromStdU16String(u16string(1, ch));
        QString count_str = QString::number(count);
        QString result = ch_str + ": " + count_str + "\n";
        ui->ptext_text_edit_t1->appendPlainText(result);
    }
}
