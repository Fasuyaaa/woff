import re
import os
import os.path
import argparse
import platform
import collections
import pkg_resources

import woff.networking.utils as netutils
from woff.menus.main_menu import MainMenu
from woff.console.banner import get_main_banner
from woff.console.io import IO


InitialArguments = collections.namedtuple('InitialArguments', 'interface, gateway_ip, netmask, gateway_mac')


def get_init_content():
    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), '__init__.py'), 'r') as f:
        return f.read()


def get_version():
    version_match = re.search(r'^__version__ = [\'"](\d\.\d\.\d)[\'"]', get_init_content(), re.M)
    if version_match:
        return version_match.group(1)
    
    raise RuntimeError('Tidak dapat menemukan string versi.')


def get_description():
    desc_match = re.search(r'^__description__ = [\'"]((.)*)[\'"]', get_init_content(), re.M)
    if desc_match:
        return desc_match.group(1)
    
    raise RuntimeError('Tidak dapat menemukan string deskripsi.')


def is_privileged():
    return os.geteuid() == 0


def is_linux():
    return platform.system() == 'Linux'


def parse_arguments():
    """
    Mem-parsing argumen baris perintah utama (sys.argv)
    menggunakan argparse
    """
    parser = argparse.ArgumentParser(description=get_description())
    parser.add_argument('-i', '--interface', help='network interface connected to the target network. automatically resolved if not specified.')
    parser.add_argument('-g', '--gateway-ip', dest='gateway_ip', help='default gateway ip address. automatically resolved if not specified.')
    parser.add_argument('-m', '--gateway-mac', dest='gateway_mac', help='gateway mac address. automatically resolved if not specified.')
    parser.add_argument('-n', '--netmask', help='netmask for the network. automatically resolved if not specified.')
    parser.add_argument('-f', '--flush', action='store_true', help='flush current iptables (firewall) and tc (traffic control) settings.')
    parser.add_argument('--colorless', action='store_true', help='disable colored output.')

    return parser.parse_args()


def process_arguments(args):
    """
    Memproses argumen baris perintah yang ditentukan, menambahkannya ke tuple bernama
    dan kembali.
    Menjalankan tindakan yang ditentukan dalam baris perintah, contoh: pengaturan jaringan flush
    """
    if args.interface is None:
        interface = netutils.get_default_interface()
        if interface is None:
            IO.error('antarmuka default tidak dapat diselesaikan. tentukan secara manual (-i).')
            return
    else:
        interface = args.interface
        if not netutils.exists_interface(interface):
            IO.error('interface {}{}{} tidak ditemukan.'.format(IO.Fore.LIGHTYELLOW_EX, interface, IO.Style.RESET_ALL))
            return

    IO.ok('interface: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, interface, IO.Style.RESET_ALL))

    if args.gateway_ip is None:
        gateway_ip = netutils.get_default_gateway()
        if gateway_ip is None:
            IO.error('alamat gateway default tidak dapat diselesaikan. tentukan secara manual (-g).')
            return
    else:
        gateway_ip = args.gateway_ip

    IO.ok('gateway ip: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, gateway_ip, IO.Style.RESET_ALL))

    if args.gateway_mac is None:
        gateway_mac = netutils.get_mac_by_ip(interface, gateway_ip)
        if gateway_mac is None:
            IO.error('alamat mac gateway tidak dapat diselesaikan.')
            return
    else:
        if netutils.validate_mac_address(args.gateway_mac):
            gateway_mac = args.gateway_mac.lower()
        else:
            IO.error('gateway mac tidak sesuai.')
            return

    IO.ok('gateway mac: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, gateway_mac, IO.Style.RESET_ALL))

    if args.netmask is None:
        netmask = netutils.get_default_netmask(interface)
        if netmask is None:
            IO.error('netmask tidak dapat diselesaikan. tentukan secara manual (-n).')
            return
    else:
        netmask = args.netmask

    IO.ok('netmask: {}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, netmask, IO.Style.RESET_ALL))

    if args.flush:
        netutils.flush_network_settings(interface)
        IO.spacer()
        IO.ok('flushed network settings')

    return InitialArguments(interface=interface, gateway_ip=gateway_ip, gateway_mac=gateway_mac, netmask=netmask)


def initialize(interface):
    """
    Menyiapkan persyaratan, contoh: Penerusan IP, aplikasi pihak ketiga
    """
    if not netutils.create_qdisc_root(interface):
        IO.spacer()
        IO.error('pegangan root qdisc tidak dapat dibuat. mungkin pengaturan jaringan flush (--flush).')
        return False

    if not netutils.enable_ip_forwarding():
        IO.spacer()
        IO.error('penerusan ip tidak dapat diaktifkan.')
        return False

    return True


def cleanup(interface):
    """
    Mengatur ulang apa yang telah diinisialisasi
    """
    netutils.delete_qdisc_root(interface)
    netutils.disable_ip_forwarding()


def run():
    """
    Titik masuk utama aplikasi
    """
    version = get_version()
    args = parse_arguments()

    IO.initialize(args.colorless)
    IO.print(get_main_banner(version))

    if not is_linux():
        IO.error('jalankan di linux.')
        return

    if not is_privileged():
        IO.error('jalankan di root.')
        return

    args = process_arguments(args)

    if args is None:
        return
    
    if initialize(args.interface):
        IO.spacer()        
        menu = MainMenu(version, args.interface, args.gateway_ip, args.gateway_mac, args.netmask)
        menu.start()
        cleanup(args.interface)


if __name__ == '__main__':
    run()