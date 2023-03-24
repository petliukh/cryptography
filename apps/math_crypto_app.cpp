#include "views/math_crypto.h"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication a(argc, argv);
    Math_crypto w;
    w.show();
    return a.exec();
}
