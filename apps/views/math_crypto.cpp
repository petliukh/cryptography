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
    this->setWindowTitle("Math Crypto - " + filename);
    m_controller.read_file();

    QPlainTextEdit* tedit = get_text_edit_to_save();
    tedit->setPlainText(QString::fromStdString(m_controller.get_filecontent()));
}

void math_crypto::on_save_action_triggered() {
    std::string content;

    if (ui->bytes_cbox->isChecked()) {
        content = get_bytes_to_save();
    } else {
        QPlainTextEdit* tedit = get_text_edit_to_save();
        content = tedit->toPlainText().toStdString();
    }

    if (m_controller.get_filename().empty()) {
        QMessageBox::warning(this, "Warning", "No filename to save.");
        return;
    }
    if (content.empty()) {
        QMessageBox::warning(this, "Warning", "No content to save.");
        return;
    }

    m_controller.set_filecontent_save(content);
    m_controller.save_file();
    QMessageBox::information(this, "Information", "File saved.");
}

void math_crypto::on_saveas_action_triggered() {
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString filename = dialog.getSaveFileName(this, "Save File As");
    std::string filename_str = filename.toStdString();
    std::string content;

    if (ui->bytes_cbox->isChecked()) {
        content = get_bytes_to_save();
    } else {
        QPlainTextEdit* tedit = get_text_edit_to_save();
        content = tedit->toPlainText().toStdString();
    }

    if (filename_str.empty()) {
        QMessageBox::warning(this, "Warning", "No filename to save.");
        return;
    }
    if (content.empty()) {
        QMessageBox::warning(this, "Warning", "No text to save.");
        return;
    }

    m_controller.set_filename(filename_str);
    this->setWindowTitle("Math Crypto - " + filename);
    m_controller.set_filecontent_save(content);
    m_controller.save_file();
}

void math_crypto::on_create_new_action_triggered() {
    ui->initial_txt_edit->clear();
    ui->encrypted_txt_edit->clear();
    ui->decrypted_txt_edit->clear();
    ui->key_ln_edit->clear();

    ui->lang_cbox->setCurrentIndex(0);
    ui->cipher_cbox->setCurrentIndex(0);
    ui->bytes_cbox->setChecked(false);
    ui->cipher_specific_ops_stacked_widget->setCurrentIndex(0);

    m_controller.set_filename("");
    this->setWindowTitle("Math Crypto");
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

QPlainTextEdit* math_crypto::get_text_edit_to_save() const {
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

std::string math_crypto::get_bytes_to_save() const {
    int idx = ui->savefile_btn_group->checkedId();
    switch (idx) {
    case 0:
        return m_controller.get_filecontent();
    case 1:
        return m_controller.get_filecontent_enc();
    case 2:
        return m_controller.get_filecontent_dec();
    default:
        return "";
    }
}

// ===========================================================================
//                             Cipher Buttons Slots
// ===========================================================================

void math_crypto::on_encrypt_btn_clicked() {
    std::string key = ui->key_ln_edit->text().toStdString();

    try {
        m_controller.set_key(key);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Warning", "Invalid key.");
        return;
    }

    if (ui->bytes_cbox->isChecked()) {
        std::string bytes = m_controller.get_filecontent();
        std::string enc_bytes = m_controller.encrypt_raw_bytes(bytes);
        m_controller.set_filecontent_enc(enc_bytes);
        ui->encrypted_txt_edit->setPlainText(QString::fromStdString(enc_bytes));
        return;
    }

    std::string cont = ui->initial_txt_edit->toPlainText().toStdString();
    std::string enc_cont = m_controller.encrypt(cont);
    ui->encrypted_txt_edit->setPlainText(QString::fromStdString(enc_cont));
}

void math_crypto::on_decrypt_btn_clicked() {
    std::string key = ui->key_ln_edit->text().toStdString();

    try {
        m_controller.set_key(key);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Warning", "Invalid key.");
        return;
    }

    if (ui->bytes_cbox->isChecked()) {
        std::string bytes = m_controller.get_filecontent_enc();
        std::string dec_bytes = m_controller.decrypt_raw_bytes(bytes);
        m_controller.set_filecontent_dec(dec_bytes);
        ui->decrypted_txt_edit->setPlainText(QString::fromStdString(dec_bytes));
        return;
    }

    std::string cont = ui->encrypted_txt_edit->toPlainText().toStdString();
    std::string dec_cont = m_controller.decrypt(cont);
    ui->decrypted_txt_edit->setPlainText(QString::fromStdString(dec_cont));
}

void math_crypto::on_bruteforce_btn_clicked() {
}

void math_crypto::on_print_freq_clicked() {
}

void math_crypto::on_cipher_cbox_currentIndexChanged(int index) {
    ui->cipher_specific_ops_stacked_widget->setCurrentIndex(index);
    m_controller.set_cipher(index);
}

void math_crypto::on_bytes_cbox_stateChanged(int arg1) {
    ui->lang_cbox->setEnabled(arg1 == Qt::Unchecked);
    ui->initial_txt_edit->setEnabled(arg1 == Qt::Unchecked);
    ui->encrypted_txt_edit->setEnabled(arg1 == Qt::Unchecked);
    ui->decrypted_txt_edit->setEnabled(arg1 == Qt::Unchecked);
}

void math_crypto::on_lang_cbox_currentIndexChanged(const QString& arg1) {
    m_controller.set_lang(arg1.toStdString());
}
