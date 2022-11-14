import time
import socket
import curses
import netaddr
import threading
import collections
from terminaltables import SingleTable

import woff.networking.utils as netutils
from .menu import CommandMenu
from woff.networking.utils import BitRate
from woff.console.io import IO
from woff.console.chart import BarChart
from woff.console.banner import get_main_banner
from woff.networking.host import Host
from woff.networking.limit import Limiter, Direction
from woff.networking.spoof import ARPSpoofer
from woff.networking.scan import HostScanner
from woff.networking.monitor import BandwidthMonitor
from woff.networking.watch import HostWatcher


class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = '({}主要 Standby{}) >>> '.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        self.parser.add_subparser('c', self._clear_handler)

        hosts_parser = self.parser.add_subparser('h', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('s', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')

        limit_parser = self.parser.add_subparser('l', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')

        block_parser = self.parser.add_subparser('b', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')

        free_parser = self.parser.add_subparser('f', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('ad', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('m', self._monitor_handler)
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        analyze_parser = self.parser.add_subparser('an', self._analyze_handler)
        analyze_parser.add_parameter('id')
        analyze_parser.add_parameterized_flag('--duration', 'duration')

        watch_parser = self.parser.add_subparser('w', self._watch_handler)
        watch_add_parser = watch_parser.add_subparser('ad', self._watch_add_handler)
        watch_add_parser.add_parameter('id')
        watch_remove_parser = watch_parser.add_subparser('r', self._watch_remove_handler)
        watch_remove_parser.add_parameter('id')
        watch_set_parser = watch_parser.add_subparser('set', self._watch_set_handler)
        watch_set_parser.add_parameter('attribute')
        watch_set_parser.add_parameter('value')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        self.parser.add_subparser('q', self._quit_handler)
        self.parser.add_subparser('e', self._quit_handler)

        self.version = version        
        self.interface = interface     
        self.gateway_ip = gateway_ip 
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        # range of IP address calculated from gateway IP and netmask
        self.iprange = list(netaddr.IPNetwork('{}/{}'.format(self.gateway_ip, self.netmask)))

        self.host_scanner = HostScanner(self.interface, self.iprange)
        self.arp_spoofer = ARPSpoofer(self.interface, self.gateway_ip, self.gateway_mac)
        self.limiter = Limiter(self.interface)
        self.bandwidth_monitor = BandwidthMonitor(self.interface, 1)
        self.host_watcher = HostWatcher(self.host_scanner, self._reconnect_callback)

        # holds discovered hosts
        self.hosts = []
        self.hosts_lock = threading.Lock()

        self._print_help_reminder()

        # start the spoof thread
        self.arp_spoofer.start()
        # start the bandwidth monitor thread
        self.bandwidth_monitor.start()
        # start the host watch thread
        self.host_watcher.start()

    def interrupt_handler(self, ctrl_c=True):
        if ctrl_c:
            IO.spacer()

        IO.ok('Membersihkan......')

        self.arp_spoofer.stop()
        self.bandwidth_monitor.stop()

        for host in self.hosts:
            self._free_host(host)

    def _scan_handler(self, args):
        """
        Gunakan 's' untuk men-scan pengguna yang tersedia
        """
        if args.iprange:
            iprange = self._parse_iprange(args.iprange)
            if iprange is None:
                IO.error('ip range tidak sesuai.')
                return
        else:
            iprange = None

        with self.hosts_lock:
            for host in self.hosts:
                self._free_host(host)
            
        IO.spacer()
        hosts = self.host_scanner.scan(iprange)

        self.hosts_lock.acquire()
        self.hosts = hosts
        self.hosts_lock.release()

        IO.ok('{}{}{} pengguna yang tersedia.'.format(IO.Fore.LIGHTYELLOW_EX, len(hosts), IO.Style.RESET_ALL))
        IO.spacer()

    def _hosts_handler(self, args):
        """
        Gunakan 'h' untuk melakukan cek daftar pengguna jaringan
        """
        table_data = [[
            '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Alamat IP{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Alamat MAC{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Pengguna{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
            '{}Keadaan Jaringan{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
        ]]
        
        with self.hosts_lock:
            for host in self.hosts:
                table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host, lock=False), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac,
                    host.name,
                    host.pretty_status()
                ])

        table = SingleTable(table_data, 'Pengguna')

        if not args.force and not table.ok:
            IO.error('Table tidak dapat dimuat di terminal. Coba paksakan layar (--force).')
            return

        IO.spacer()
        IO.print(table.table)
        IO.spacer()

    def _limit_handler(self, args):
        """
        Gunakan 'l' untuk memberikan batasan kepada pengguna
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        try:
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('limit rate tidak sesuai.')
            return

        direction = self._parse_direction_args(args)

        for host in hosts:
            self.arp_spoofer.add(host)
            self.limiter.limit(host, direction, rate)
            self.bandwidth_monitor.add(host)

            IO.ok('{}{}{r} {} {}limited{r} to {}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.LIGHTRED_EX, rate, r=IO.Style.RESET_ALL))

    def _block_handler(self, args):
        """
        Gunakan 'b' untuk menonaktifkan akses pengguna ke jaringan
        """
        hosts = self._get_hosts_by_ids(args.id)
        direction = self._parse_direction_args(args)

        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.block(host, direction)
                self.bandwidth_monitor.add(host)
                IO.ok('{}{}{r} {} {}blocked{r}.'.format(IO.Fore.LIGHTYELLOW_EX, host.ip, Direction.pretty_direction(direction), IO.Fore.RED, r=IO.Style.RESET_ALL))

    def _free_handler(self, args):
        """
        Gunakan 'f' untuk memberikan akses jaringan ke pengguna
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is not None and len(hosts) > 0:
            for host in hosts:
                self._free_host(host)

    def _add_handler(self, args):
        """
        Gunakan 'ad' untuk menambahkan pengguna ke dalam daftar pengguna
        """
        ip = args.ip
        if not netutils.validate_ip_address(ip):
            IO.error('alamat ip tidak sesuai.')
            return

        if args.mac:
            mac = args.mac
            if not netutils.validate_mac_address(mac):
                IO.error('alamat mac tidak sesuai.')
                return
        else:
            mac = netutils.get_mac_by_ip(self.interface, ip)
            if mac is None:
                IO.error('matikan untuk menyelesaikan masalah alamat mac. Selesaikan secara manual (--mac).')
                return

        name = None
        try:
            host_info = socket.gethostbyaddr(ip)
            name = None if host_info is None else host_info[0]
        except socket.herror:
            pass

        host = Host(ip, mac, name)

        with self.hosts_lock:
            if host in self.hosts:
                IO.error('pengguna sudah tersedia.')
                return

            self.hosts.append(host) 

        IO.ok('pengguna ditambahkan.')

    def _monitor_handler(self, args):
        """
        Gunakan 'm' untuk memonitoring penggunaan bandwidth oleh pengguna
        """
        def get_bandwidth_results():
            with self.hosts_lock:
                return [x for x in [(y, self.bandwidth_monitor.get(y)) for y in self.hosts] if x[1] is not None]

        def display(stdscr, interval):
            host_results = get_bandwidth_results()
            hname_max_len = max([len(x[0].name) for x in host_results])

            header_off = [
                ('ID', 5), ('Alamat MAC', 18), ('Pengguna', hname_max_len + 2),
                ('Current (per s)', 20), ('Total', 16), ('Paket', 0)
            ]

            y_rst = 1
            x_rst = 2

            while True:
                y_off = y_rst
                x_off = x_rst

                stdscr.clear()

                for header in header_off:
                    stdscr.addstr(y_off, x_off, header[0])
                    x_off += header[1]

                y_off += 2
                x_off = x_rst

                for host, result in host_results:
                    result_data = [
                        str(self._get_host_id(host)),
                        host.ip,
                        host.name,
                        '{}↑ {}↓'.format(result.upload_rate, result.download_rate),
                        '{}↑ {}↓'.format(result.upload_total_size, result.download_total_size),
                        '{}↑ {}↓'.format(result.upload_total_count, result.download_total_count)
                    ]

                    for j, string in enumerate(result_data):
                        stdscr.addstr(y_off, x_off, string)
                        x_off += header_off[j][1]

                    y_off += 1
                    x_off = x_rst

                y_off += 2
                stdscr.addstr(y_off, x_off, 'Tekan \'ctrl+c\' untuk keluar.')

                try:
                    stdscr.refresh()
                    time.sleep(interval)
                    host_results = get_bandwidth_results()
                except KeyboardInterrupt:
                    return
                    

        interval = 0.5  # in s
        if args.interval:
            if not args.interval.isdigit():
                IO.error('Interval tidak cocok.')
                return

            interval = int(args.interval) / 1000    # from ms to s

        if len(get_bandwidth_results()) == 0:
            IO.error('tidak ada pengguna yang dapat dimonitoring.')
            return

        try:
            curses.wrapper(display, interval)
        except curses.error:
            IO.error('Monitor error, terminal terlalu kecil')

    def _analyze_handler(self, args):
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            IO.error('tidak ada pengguna yang dipantau.')
            return
        
        duration = 30 # in s
        if args.duration:
            if not args.duration.isdigit():
                IO.error('duration tidak sesuai.')
                return

            duration = int(args.duration)

        hosts_to_be_freed = set()
        host_values = {}

        for host in hosts:
            if not host.spoofed:
                hosts_to_be_freed.add(host)

            self.arp_spoofer.add(host)
            self.bandwidth_monitor.add(host)

            host_result = self.bandwidth_monitor.get(host)
            host_values[host] = {}
            host_values[host]['sebelumnya'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('analyzing jalur untuk {}s.'.format(duration))
        time.sleep(duration)

        error_occurred = False
        for host in hosts:
            host_result = self.bandwidth_monitor.get(host)

            if host_result is None:
                IO.error('pengguna menyambung ulang saat analysis.')
                error_occurred = True
            else:
                host_values[host]['saat ini'] = (host_result.upload_total_size, host_result.download_total_size)

        IO.ok('membersihkan...')
        for host in hosts_to_be_freed:
            self._free_host(host)

        if error_occurred:
            return

        upload_chart = BarChart(max_bar_length=29)
        download_chart = BarChart(max_bar_length=29)

        for host in hosts:
            upload_value = host_values[host]['saat ini'][0] - host_values[host]['sebelumnya'][0]
            download_value = host_values[host]['saat ini'][1] - host_values[host]['sebelumnya'][1]

            prefix = '{}{}{} ({}, {})'.format(
                IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL,
                host.ip,
                host.name
            )
            
            upload_chart.add_value(upload_value.value, prefix, upload_value)
            download_chart.add_value(download_value.value, prefix, download_value)

        upload_table = SingleTable([[upload_chart.get()]], 'Upload')
        download_table = SingleTable([[download_chart.get()]], 'Download')

        upload_table.inner_heading_row_border = False
        download_table.inner_heading_row_border = False

        IO.spacer()
        IO.print(upload_table.table)
        IO.print(download_table.table)
        IO.spacer()

    def _watch_handler(self, args):
        if len(args) == 0:
            watch_table_data = [[
                '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Alamat IP{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Alamat MAC{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            set_table_data = [[
                '{}Attribute{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Value{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            hist_table_data = [[
                '{}ID{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Alamat IP lama{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Alamat IP baru{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL),
                '{}Time{}'.format(IO.Style.BRIGHT, IO.Style.RESET_ALL)
            ]]

            iprange = self.host_watcher.iprange
            interval = self.host_watcher.interval

            set_table_data.append([
                '{}range{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
                '{} alamat'.format(len(iprange)) if iprange is not None else 'default'
            ])

            set_table_data.append([
                '{}interval{}'.format(IO.Fore.LIGHTYELLOW_EX, IO.Style.RESET_ALL),
                '{}s'.format(interval)
            ])

            for host in self.host_watcher.hosts:
                watch_table_data.append([
                    '{}{}{}'.format(IO.Fore.LIGHTYELLOW_EX, self._get_host_id(host), IO.Style.RESET_ALL),
                    host.ip,
                    host.mac
                ])

            for recon in self.host_watcher.log_list:
                hist_table_data.append([
                    recon['lama'].mac,
                    recon['lama'].ip,
                    recon['baru'].ip,
                    recon['time']
                ])

            watch_table = SingleTable(watch_table_data, "Watchlist")
            set_table = SingleTable(set_table_data, "Settings")
            hist_table = SingleTable(hist_table_data, 'Riwayat penyambungan ulang')

            IO.spacer()
            IO.print(watch_table.table)
            IO.spacer()
            IO.print(set_table.table)
            IO.spacer()
            IO.print(hist_table.table)
            IO.spacer()

    def _watch_add_handler(self, args):
        """
        Gunakan 'watch add' untuk menambahkan nama pengguna ke dalam daftar pengguna yang menyambungkan ulang
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.add(host)

    def _watch_remove_handler(self, args):
        """
        Gunakan 'watch remove' untuk menghapus nama pengguna dari dalam daftar pengguna yang menyambungkan ulang
        """
        hosts = self._get_hosts_by_ids(args.id)
        if hosts is None or len(hosts) == 0:
            return

        for host in hosts:
            self.host_watcher.remove(host)

    def _watch_set_handler(self, args):
        """
        Gunakan 'watch set' untuk mengatur pengguna yang melakukan penyambungan ulang
        """
        if args.attribute.lower() in ('range', 'iprange', 'ip_range'):
            iprange = self._parse_iprange(args.value)
            if iprange is not None:
                self.host_watcher.iprange = iprange
            else:
                IO.error('ip range tidak sesuai.')
        elif args.attribute.lower() in ('interval'):
            if args.value.isdigit():
                self.host_watcher.interval = int(args.value)
            else:
                IO.error('interval tidak sesuai.')
        else:
            IO.error('{}{}{} kesalahan settings attribute.'.format(IO.Fore.LIGHTYELLOW_EX, args.attribute, IO.Style.RESET_ALL))

    def _reconnect_callback(self, old_host, new_host):
        """
        Panggilan balik yang dipanggil saat host yang ditonton terhubung kembali
        Metode akan berjalan di utas terpisah
        """
        with self.hosts_lock:
            if old_host in self.hosts:
                self.hosts[self.hosts.index(old_host)] = new_host
            else:
                return

        self.arp_spoofer.remove(old_host, restore=False)
        self.arp_spoofer.add(new_host)

        self.host_watcher.remove(old_host)
        self.host_watcher.add(new_host)

        self.limiter.replace(old_host, new_host)
        self.bandwidth_monitor.replace(old_host, new_host)

    def _clear_handler(self, args):
        """
        Gunakan 'c' untuk membersihkan terminal
        """
        IO.clear()
        IO.print(get_main_banner(self.version))
        self._print_help_reminder()

    def _help_handler(self, args):
        """
        Gunakan 'help' untuk melihat fungsi command line
        """
        spaces = ' ' * 35

        IO.print(
            """
{y}s (--range [IP range]){r}{}memindai pengguna online di jaringan Anda.
{s}diperlukan untuk menemukan pengguna yang ingin Anda batasi.
{b}{s}contoh: s
{s}      s --range 192.168.178.1-192.168.178.50
{s}      s --range 192.168.178.1/24{r}

{y}h (--force){r}{}menampilkan semua pengguna yang terhubung.
{s}berisi informasi pengguna, termasuk ID.

{y}l [ID1,ID2,...] [rate]{r}{}membatasi bandwidth pengguna(s) (uload/dload).
{y}      (--upload) (--download){r}{}{b}contoh: l 4 100kbit
{s}     l 2,3,4 1gbit --download
{s}      l all 200kbit --upload{r}

{y}b [ID1,ID2,...]{r}{}batasi akses internet pengguna(s).
{y}      (--upload) (--download){r}{}{b}contoh: b 3,2
{s}      b all --upload{r}

{y}f [ID1,ID2,...]{r}{}buka batasan akses pengguna(s).
{b}{s}contoh: f 3
{s}      f all{r}

{y}ad [IP] (--mac [MAC]){r}{}tambahkan pengguna ke list.
{s}penyelesaian mac otomatis.
{b}{s}cotoh: ad 192.168.178.24
{s}      ad 192.168.1.50 --mac 1c:fc:bc:2d:a6:37{r}

{y}m (--interval [time in ms]){r}{}monitoring bengguna dan batasi(s).
{b}{s}contoh: m --interval 600{r}

{y}an [ID1,ID2,...]{r}{}analyzes jalur pengguna(s) tanpa limit
{y}        (--duration [time in s]){r}{}untuk menentukan siapa yang menggunakan berapa banyak bandwidth.
{b}{s}contoh: an 2,3 --duration 120{r}

{y}w{r}{}mendeteksi pengguna terhubung kembali dengan IP yang berbeda.
{y}watch add [ID1,ID2,...]{r}{}menambahkan pengguna ke daftar pantauan rekoneksi.
{b}{s}contoh: watch add 3,4{r}
{y}watch remove [ID1,ID2,...]{r}{}menghapus pengguna dari daftar pantauan rekoneksi.
{b}{s}contoh: watch remove all{r}
{y}watch set [attr] [value]{r}{}mengubah pengaturan menghubungkan kembali.
{b}{s}contoh: watch set interval 120{r}

{y}c{r}{}bersihkan terminal.

{y}q{r}{}keluar program.
            """.format(
                    spaces[len('s (--range [IP range])'):],
                    spaces[len('h (--force)'):],
                    spaces[len('l [ID1,ID2,...] [rate]'):],
                    spaces[len('      (--upload) (--download)'):],
                    spaces[len('b [ID1,ID2,...]'):],
                    spaces[len('      (--upload) (--download)'):],
                    spaces[len('f [ID1,ID2,...]'):],
                    spaces[len('ad [IP] (--mac [MAC])'):],
                    spaces[len('m (--interval [time in ms])'):],
                    spaces[len('an [ID1,ID2,...]'):],
                    spaces[len('        (--duration [time in s])'):],
                    spaces[len('w'):],
                    spaces[len('watch add [ID1,ID2,...]'):],
                    spaces[len('watch remove [ID1,ID2,...]'):],
                    spaces[len('watch set [attr] [value]'):],
                    spaces[len('c'):],
                    spaces[len('q'):],
                    y=IO.Fore.LIGHTYELLOW_EX, r=IO.Style.RESET_ALL, b=IO.Style.BRIGHT,
                    s=spaces
                )
        )

    def _quit_handler(self, args):
        self.interrupt_handler(False)
        self.stop()

    def _get_host_id(self, host, lock=True):
        ret = None

        if lock:
            self.hosts_lock.acquire()

        for i, host_ in enumerate(self.hosts):
            if host_ == host:
                ret = i
                break
        
        if lock:
            self.hosts_lock.release()

        return ret

    def _print_help_reminder(self):
        IO.print('ketik {Y}?{R} atau {Y}help{R} menunjukkan informasi command line.'.format(Y=IO.Fore.LIGHTYELLOW_EX, R=IO.Style.RESET_ALL))

    def _get_hosts_by_ids(self, ids_string):
        if ids_string == 'all':
            with self.hosts_lock:
                return self.hosts.copy()

        ids = ids_string.split(',')
        hosts = set()

        with self.hosts_lock:
            for id_ in ids:
                is_mac = netutils.validate_mac_address(id_)
                is_ip = netutils.validate_ip_address(id_)
                is_id_ = id_.isdigit()

                if not is_mac and not is_ip and not is_id_:
                    IO.error('identifier(s) tidak sesuai: \'{}\'.'.format(ids_string))
                    return

                if is_mac or is_ip:
                    found = False
                    for host in self.hosts:
                        if host.mac == id_.lower() or host.ip == id_:
                            found = True
                            hosts.add(host)
                            break
                    if not found:
                        IO.error('tidak ditemukan pengguna {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                        return
                else:
                    id_ = int(id_)
                    if len(self.hosts) == 0 or id_ not in range(len(self.hosts)):
                        IO.error('tidak ada pengguna dengan id {}{}{}.'.format(IO.Fore.LIGHTYELLOW_EX, id_, IO.Style.RESET_ALL))
                        return
                    hosts.add(self.hosts[id_])

        return hosts

    def _parse_direction_args(self, args):
        direction = Direction.NONE

        if args.upload:
            direction |= Direction.OUTGOING
        if args.download:
            direction |= Direction.INCOMING

        return Direction.BOTH if direction == Direction.NONE else direction

    def _parse_iprange(self, range):
        try:
            if '-' in range:
                return list(netaddr.iter_iprange(*range.split('-')))
            else:
                return list(netaddr.IPNetwork(range))
        except netaddr.core.AddrFormatError:
            return

    def _free_host(self, host):
        """
        Menghentikan spoofing ARP dan membatasi pengguna
        """
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.limiter.unlimit(host, Direction.BOTH)
            self.bandwidth_monitor.remove(host)
            self.host_watcher.remove(host)
