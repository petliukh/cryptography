#include "math_crypto.h"

Math_crypto::Math_crypto(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::Math_crypto)
{
    ui->setupUi(this);
    ui->savefile_btn_group->setId(ui->initial_rbtn, 0);
    ui->savefile_btn_group->setId(ui->encrypted_rbtn, 1);
    ui->savefile_btn_group->setId(ui->decrypted_rbtn, 2);
}

Math_crypto::~Math_crypto()
{
    delete ui;
}

// ===========================================================================
//                             Meny Bar Slots
// ===========================================================================

void Math_crypto::on_open_action_triggered()
{
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFile);
    QString filename = dialog.getOpenFileName(this, "Open File");

    if (filename.isEmpty()) {
        QMessageBox::warning(this, "Warning", "No filename to open.");
        return;
    }

    m_controller.set_filename(filename.toStdString());
    m_controller.set_curr_state(ui->savefile_btn_group->checkedId());
    QPlainTextEdit* tedit = get_curr_text_edit();
    tedit->setPlainText(QString::fromStdString(m_controller.read_file()));
    this->setWindowTitle("Math Crypto - " + filename);
}

void Math_crypto::on_save_action_triggered()
{
    if (m_controller.get_filename().empty()) {
        QMessageBox::warning(this, "Warning", "No filename to save.");
        return;
    }

    if (ui->bytes_cbox->isChecked()) {
        m_controller.save_file(ui->savefile_btn_group->checkedId());
    } else {
        QPlainTextEdit* txt_edit = get_curr_text_edit();
        QString text = txt_edit->toPlainText();
        m_controller.save_file(text.toStdString());
    }
    QMessageBox::information(this, "Information", "File saved.");
}

void Math_crypto::on_saveas_action_triggered()
{
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString filename = dialog.getSaveFileName(this, "Save File");

    if (filename.isEmpty()) {
        QMessageBox::warning(this, "Warning", "No filename to save.");
        return;
    }

    m_controller.set_filename(filename.toStdString());
    if (ui->bytes_cbox->isChecked()) {
        m_controller.save_file(ui->savefile_btn_group->checkedId());
    } else {
        QPlainTextEdit* txt_edit = get_curr_text_edit();
        QString text = txt_edit->toPlainText();
        m_controller.save_file(text.toStdString());
    }
    QMessageBox::information(this, "Information", "File saved.");
}

void Math_crypto::on_create_new_action_triggered()
{
    ui->initial_txt_edit->clear();
    ui->encrypted_txt_edit->clear();
    ui->decrypted_txt_edit->clear();
    ui->key_ln_edit->clear();

    ui->lang_cbox->setCurrentIndex(0);
    ui->cipher_cbox->setCurrentIndex(0);
    ui->bytes_cbox->setChecked(false);
    ui->cipher_specific_ops_stacked_widget->setCurrentIndex(0);
    ui->freq_table_widget->clear();
    this->setWindowTitle("Math Crypto");
    m_controller.reset();
}

void Math_crypto::on_print_action_triggered()
{
    QMessageBox::warning(this, "Warning", "Not implemented yet.");
}

void Math_crypto::on_about_action_triggered()
{
    QMessageBox::about(
            this, "About Math Cryptography",
            "This program is designed to encrypt and "
            "decrypt messages using different ciphers. ");
}

void Math_crypto::on_exit_action_triggered()
{
    QApplication::quit();
}

// ===========================================================================
//                             Getters
// ===========================================================================

QPlainTextEdit* Math_crypto::get_curr_text_edit() const
{
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

void Math_crypto::on_encrypt_btn_clicked()
{
    std::string key = ui->key_ln_edit->text().toStdString();
    try {
        m_controller.set_key(key);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Warning", "Invalid key.");
        return;
    }

    if (ui->bytes_cbox->isChecked()) {
        std::string to_enc = m_controller.get_content(0);
        std::string enc_bytes = m_controller.encrypt_raw_bytes(to_enc);
        m_controller.set_content(1, enc_bytes);
        ui->encrypted_txt_edit->setPlainText(QString::fromStdString(enc_bytes));
        return;
    }

    QString cont = ui->initial_txt_edit->toPlainText();
    std::string enc_cont = m_controller.encrypt(cont.toStdString());
    ui->encrypted_txt_edit->setPlainText(QString::fromStdString(enc_cont));
}

void Math_crypto::on_decrypt_btn_clicked()
{
    std::string key = ui->key_ln_edit->text().toStdString();
    try {
        m_controller.set_key(key);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Warning", "Invalid key.");
        return;
    }

    if (ui->bytes_cbox->isChecked()) {
        std::string to_dec = m_controller.get_content(1);
        std::string dec_bytes = m_controller.decrypt_raw_bytes(to_dec);
        m_controller.set_content(2, dec_bytes);
        ui->decrypted_txt_edit->setPlainText(QString::fromStdString(dec_bytes));
        return;
    }

    QString cont = ui->encrypted_txt_edit->toPlainText();
    std::string dec_cont = m_controller.decrypt(cont.toStdString());
    ui->decrypted_txt_edit->setPlainText(QString::fromStdString(dec_cont));
}

void Math_crypto::on_brute_force_btn_clicked()
{
    if (ui->bytes_cbox->isChecked()) {
        QMessageBox::warning(this, "Warning", "Cannot brute force bytes.");
        return;
    }

    QString text = ui->encrypted_txt_edit->toPlainText();
    auto brute_res = m_controller.brute_force(text.toStdString());
    ui->brute_force_table->clear();
    ui->brute_force_table->setRowCount(brute_res.size());
    ui->brute_force_table->setColumnCount(2);
    int row = 0;

    for (auto& [k, v] : brute_res) {
        ui->brute_force_table->setItem(
                row, 0, new QTableWidgetItem(QString::number(k)));
        ui->brute_force_table->setItem(
                row, 1, new QTableWidgetItem(QString::fromStdString(v)));
        row++;
    }
}

void Math_crypto::on_print_freq_clicked()
{
    if (ui->bytes_cbox->isChecked()) {
        QMessageBox::warning(
                this, "Warning", "Cannot print frequencies of bytes.");
        return;
    }

    int idx = ui->savefile_btn_group->checkedId();
    QString text = get_curr_text_edit()->toPlainText();
    auto freqs = m_controller.calc_freqs(text.toStdString());

    ui->freq_table_widget->clear();
    ui->freq_table_widget->setRowCount(freqs.size());
    ui->freq_table_widget->setColumnCount(2);
    int row = 0;
    for (const auto& [k, v] : freqs) {
        ui->freq_table_widget->setItem(
                row, 0, new QTableWidgetItem(QString(k)));
        ui->freq_table_widget->setItem(
                row, 1, new QTableWidgetItem(QString::number(v)));
        row++;
    }
}

void Math_crypto::on_cipher_cbox_currentIndexChanged(int index)
{
    ui->cipher_specific_ops_stacked_widget->setCurrentIndex(index);
    m_controller.set_cipher_index(index);
}

void Math_crypto::on_bytes_cbox_stateChanged(int arg1)
{
    ui->lang_cbox->setEnabled(arg1 == Qt::Unchecked);
    ui->initial_txt_edit->setEnabled(arg1 == Qt::Unchecked);
    ui->encrypted_txt_edit->setEnabled(arg1 == Qt::Unchecked);
    ui->decrypted_txt_edit->setEnabled(arg1 == Qt::Unchecked);
}

void Math_crypto::on_lang_cbox_currentIndexChanged(const QString& arg1)
{
    m_controller.set_lang(arg1.toStdString());
}

void Math_crypto::on_msg_pair_attack_btn_clicked()
{
    QString input = ui->loaded_msg_pair_txt_edit->toPlainText();
    QStringList messages = input.split("\n\n");
    std::string key = m_controller.break_trithemius_cipher_key(
            messages[0].toStdString(), messages[1].toStdString());
    ui->broken_msg_txt_edit->setPlainText(QString::fromStdString(key));
}
