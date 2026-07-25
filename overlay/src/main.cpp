#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#include <tesla.hpp>
#include "GuiMain.hpp"

class OverlayWireguard : public tsl::Overlay {
  public:
    // libtesla already initialized fs, hid, pl, pmdmnt, hid:sys and set:sys
    virtual void initServices() override {
        pmshellInitialize();
    }
    virtual void exitServices() override {
        pmshellExit();
    }

    virtual void onShow() override {}
    virtual void onHide() override {}

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<GuiMain>();
    }
};

int main(int argc, char** argv) {
    return tsl::loop<OverlayWireguard>(argc, argv);
}
