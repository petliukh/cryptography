#include "math_crypto.h"

math_crypto::math_crypto(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::math_crypto) {
    ui->setupUi(this);
    ui->savefile_btn_group->setId(ui->initial_rbtn, 0);
    ui->savefile_btn_group->setId(ui->encrypted_rbtn, 1);
    ui->savefile_btn_group->setId(ui->decrypted_rbtn, 2);
}

math_crypto::~math_crypto() {
    delete ui;
}

// ===========================================================================
//                             Meny Bar Slots
// ===========================================================================

void math_crypto::on_open_action_triggered() {
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFile);
    QString filename = dialog.getOpenFileName(this, "Open File");

    if (filename.isEmpty()) {
        QMessageBox::warning(this, "Warning", "No filename to open.");
        return;
    }

    m_controller.set_filename(filename.toStdString());
    m_controller.read_file();

    QPlainTextEdit* tedit = get_text_edit_to_save();
    tedit->setPlainText(m_controller.get_filecontent().c_str());
}

void math_crypto::on_save_action_triggered() {
    QPlainTextEdit* tedit = get_text_edit_to_save();
    std::string content = tedit->toPlainText().toStdString();

    if (m_controller.get_filename().empty()) {
        QMessageBox::warning(this, "Warning", "No filename to save.");
        return;
    }
    if (content.empty()) {
        QMessageBox::warning(this, "Warning", "No text to save.");
        return;
    }

    m_controller.set_filecontent(content);
    m_controller.save_file();
}

void math_crypto::on_saveas_action_triggered() {
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString filename = dialog.getSaveFileName(this, "Save File As");
    QPlainTextEdit* tedit = get_text_edit_to_save();

    std::string filename_str = filename.toStdString();
    std::string content = tedit->toPlainText().toStdString();

    if (filename_str.empty()) {
        QMessageBox::warning(this, "Warning", "No filename to save.");
        return;
    }
    if (content.empty()) {
        QMessageBox::warning(this, "Warning", "No text to save.");
        return;
    }

    m_controller.set_filename(filename_str);
    m_controller.set_filecontent(content);
    m_controller.save_file();
}

void math_crypto::on_create_new_action_triggered() {
    ui->initial_txt_edit->clear();
    ui->encrypted_txt_edit->clear();
    ui->decrypted_txt_edit->clear();

    ui->lang_cbox->setCurrentIndex(0);
    ui->cipher_cbox->setCurrentIndex(0);
    ui->bytes_cbox->setChecked(false);
    ui->cipher_specific_ops_stacked_widget->setCurrentIndex(0);

    m_controller.set_filename("");
    m_controller.set_filecontent("");
    m_controller.set_lang("EN");
    m_controller.set_cipher(0);
}

void math_crypto::on_print_action_triggered() {
    QMessageBox::warning(this, "Warning", "Not implemented yet.");
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

// ===========================================================================
//                             Getters
// ===========================================================================

QPlainTextEdit* math_crypto::get_text_edit_to_save() {
    int idx = ui->savefile_btn_group->checkedId();

    switch (idx) {
    case 0:
        return ui->initial_txt_edit;
    case 1:
        return ui->encrypted_txt_edit;
    case 2:
        return ui->decrypted_txt_edit;
    default:
        return nullptr;
    }
}

// ===========================================================================
//                             Cipher Buttons Slots
// ===========================================================================

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
