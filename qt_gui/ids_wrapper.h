#ifndef IDS_WRAPPER_H
#define IDS_WRAPPER_H

#include <QString>

class IDSWrapper {
public:
    IDSWrapper();

    int start(QString iface);
    int stop();
    int alertCount();
    QString popAlert();
};

#endif
