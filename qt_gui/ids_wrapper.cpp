#include "ids_wrapper.h"

extern "C" {
#include "../ids_core/include/ids_api.h"
}

IDSWrapper::IDSWrapper() {}

int IDSWrapper::start(QString iface) {
    return ids_start(iface.toStdString().c_str());
}

int IDSWrapper::stop() {
    return ids_stop();
}

int IDSWrapper::alertCount() {
    return ids_get_alert_count();
}

QString IDSWrapper::popAlert() {
    char buf[256];
    if (ids_pop_alert(buf, sizeof(buf)) > 0) {
        return QString(buf);
    }
    return "";
}
