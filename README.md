<pre>
<h2> Find >/h2>
ind /path/to/dir/ -printf '%s %p\n'| sort -nr | head -10
find . -printf '%s %p\n'| sort -nr | head -10

du -hs * | sort -h | more

You can skip directories and only display files, type:

 find /path/to/search/ -type f -printf '%s %p\n'| sort -nr | head -10

 find /path/to/search/ -type f -iname "*.mp4" -printf '%s %p\n'| sort -nr | head -10
 
by size windows put in search
 size:gigantic

<h2> tar </h2>
tar cvzf Server-Log-11082021.tar.gz   /ReaR/AppTempServerLogsBakup

tar -tvf uploadprogress.tar


 <h2>user login history </h2>
 utmpdump /var/log/wtmp* | awk '$4~"mahsan" {print}'


utmpdump /var/log/wtmp* | awk  '$4~"mahsan" {print}'

systemctl list-units --type=service (List all service on RHEL7 and 8)

curl -v telnet://localhost:22  

Please check the agent service is running.
 
$ ncat -z -v lnxcastggt01.vch.ca 50051
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Connection refused.


cat /dev/null > /var/mail/root
 lsof | egrep "deleted|COMMAND"

root@lvmrhtst01 ~]# usermod -aG wheel sam02
[root@lvmrhtst01 ~]# cat /etc/group

Color prompt
export PS1="\e[1;32m\u\e[0m@\e[1;31m\h\e[0m\w$"

systemctl list-units --type service
systemctl list-units --type mount
systemctl list-unit-files

ps -eo pid,user,s,comm,size,vsize,rss --sort -size | head

 systool -c fc_host -v
 
 systool -c fc_host -v
 
 ./lssd -l

grep -R sos

chage -I -1 -m 0 -M 99999 -E -1 sudoroot [0]

for i in `cat list`l do chg -E0 $i; done

 lsblk -io NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE,MODE
 
 [mahsan@lvmnpbcgg01 ~]$ cat partdata
sdp
[mahsan@lvmnpbcgg01 ~]$ cat parted-disk.sh
#!/bin/ksh
# create_part
debug=$1
partdata=$2
echo $partdata
while read disk
do
if [ "$debug" = "commit" ]; then
   parted -s /dev/${disk} unit MiB -- mklabel gpt
   parted -s /dev//${disk} -- mkpart primary 0% 100%
   parted -s /dev/${disk} unit MiB -- print
   parted -s /dev/${disk} align-check opt 1
   ls -l /dev/${disk}*
else
  echo -e "\n"
  echo -e "parted -s /dev/${disk} unit MiB -- mklabel gpt"
  echo -e "parted -s /dev/${disk} -- mkpart primary 0% 100%"
  echo -e "parted -s /dev/${disk} unit MiB -- print"
  echo -e "ls -l /dev/${disk}*"
fi
done < $partdata

[mahsan@lvmnpbcgg01 ~]$



ov  2 14:18:38 lvmnpbcgg01 mahsan: root [21781]: bash parted-disk.sh debug partdata [0]
Nov  2 14:18:49 lvmnpbcgg01 mahsan: root [21781]: bash parted-disk.sh commit partdata [0]
 
***
root@c76~/docker-images$docker run -it -d --privileged=true linux-cups /sbin/init

docker exec -it 0230492a513d bash

[droot@zvmlinux7 test]$ ll
total 4
-rw-rw-r-- 1 droot droot 418 Oct 27 10:50 Dockerfile
[droot@zvmlinux7 test]$ cat Dockerfile
FROM centos:7
RUN yum install openssh-server openssh-clients cups vim mlocate curl wget net-tools sudo -y
RUN yum install epel-release -y
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
RUN ssh-keygen -A
RUN echo "root:centos" | chpasswd
RUN useradd test
RUN echo "test:test" | chpasswd
RUN echo "test  ALL=(ALL)  NOPASSWD: ALL" >> /etc/sudoers
CMD ["/usr/sbin/cupsd", "-D"]
CMD ["/usr/sbin/sshd", "-D"]
[droot@zvmlinux7 test]$


 sudo docker run -it -d --privileged=true -v /home/mahsan:/mnt print-queues  /sbin/init


***
systool -c scsi_host -v |egrep "lpfc_drvr_version|info|fwrev|Device"


The firmware details could be seen from the output of the command systool (provided by sysfsutils package). For example:
Raw
 #systool -c scsi_host -v |egrep "lpfc_drvr_version|info|fwrev|Device"
 Class Device = "host4"
  Class Device path = "/sys/devices/pci0000:00/0000:00:07.0/0000:0e:00.1/host4/scsi_host/host4"
    bg_info             = "BlockGuard Disabled"
    fwrev               = "2.72A2 (Z3F2.72A2), sli-3"   ------------------  firmware
    info                = "Emulex LPe11002-M4 4Gb 2port FC: PCIe SFF HBA on PCI bus 0e device 01 irq 78 port 1"
    lpfc_drvr_version   = "Emulex LightPulse Fibre Channel SCSI driver 10.2.8021.1"    ------------------------------- driver
    npiv_info           = "NPIV Physical"
    Device = "host4"
    Device path = "/sys/devices/pci0000:00/0000:00:07.0/0000:0e:00.1/host4"

OR

# d
 Class Device = "host4"
  Class Device path = "/sys/devices/pci0000:00/0000:00:07.0/0000:0e:00.1/host4/fc_host/host4"
    symbolic_name       = "Emulex LPe11002-M4 FV2.72A2 DV10.2.8021.1"     ---------- firmware(FV) and driver(DV)
    Device = "host4"
    Device path = "/sys/devices/pci0000:00/0000:00:07.0/0000:0e:00.1/host4"
In this, FV2.72A2 is the firmware and DV10.2.8021.1 is the driver.


rsync Commands

##rsync remote destination
rsync -zarvh /opt/backup/  root@rsync2:/tmp

##Show the Progress
rsync -zarvh --progress /opt/backup/  root@rsync2:/tmp

##Comapre files
rsync -avzi /home/pkumar/techi root@192.168.1.29:/opt

rsync -avzi --progress /opt/backup/  root@rsync2:/tmp
sending incremental file list
<f.st...... a1
          3,906 100%    3.06MB/s    0:00:00 (xfr#1, to-chk=7/9)


    d: indicates change in destination file
    f: indicates a file
    t: indicates change in timestamps
    s: indicates change in size


systemctl list-unit-files


[root@lnxcstsdsggt02 hp_fibreutils]# systool -c fc_host -v
Class = "fc_host"
 
  Class Device = "host1"
  Class Device path = "/sys/devices/pci0000:00/0000:00:02.0/0000:05:00.0/host1/fc_host/host1"
    active_fc4s         = "0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    dev_loss_tmo        = "30"
    fabric_name         = "0x1000889471913c59"
    issue_lip           = <store method only>
    max_npiv_vports     = "255"
    maxframe_size       = "2048 bytes"
    node_name           = "0x20000090fac12690"
    npiv_vports_inuse   = "0"
    port_id             = "0x295200"
    port_name           = "0x10000090fac12690"
    port_state          = "Online"
    port_type           = "NPort (fabric via point-to-point)"
    speed               = "8 Gbit"
    supported_classes   = "Class 3"
    supported_fc4s      = "0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    supported_speeds    = "2 Gbit, 4 Gbit, 8 Gbit"
    symbolic_name       = "Emulex AJ763B/AH403A FV2.10X6 DV12.0.0.13. HN:lnxcstsdsggt02.healthbc.org. OS:Linux"
    tgtid_bind_type     = "wwpn (World Wide Port Name)"
    uevent              =
    vport_create        = <store method only>
    vport_delete        = <store method only>
 
    Device = "host1"
    Device path = "/sys/devices/pci0000:00/0000:00:02.0/0000:05:00.0/host1"
      uevent              = "DEVTYPE=scsi_host"
 
 
  Class Device = "host2"
  Class Device path = "/sys/devices/pci0000:00/0000:00:02.0/0000:05:00.1/host2/fc_host/host2"
    active_fc4s         = "0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    dev_loss_tmo        = "30"
    fabric_name         = "0x1000889471715586"
    issue_lip           = <store method only>
    max_npiv_vports     = "255"
    maxframe_size       = "2048 bytes"
    node_name           = "0x20000090fac12691"
    npiv_vports_inuse   = "0"
    port_id             = "0x2a5200"
    port_name           = "0x10000090fac12691"
    port_state          = "Online"
    port_type           = "NPort (fabric via point-to-point)"
    speed               = "8 Gbit"
    supported_classes   = "Class 3"
    supported_fc4s      = "0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
    supported_speeds    = "2 Gbit, 4 Gbit, 8 Gbit"
    symbolic_name       = "Emulex AJ763B/AH403A FV2.10X6 DV12.0.0.13. HN:lnxcstsdsggt02.healthbc.org. OS:Linux"
    tgtid_bind_type     = "wwpn (World Wide Port Name)"
    uevent              =
    vport_create        = <store method only>
    vport_delete        = <store method only>
 
    Device = "host2"
    Device path = "/sys/devices/pci0000:00/0000:00:02.0/0000:05:00.1/host2"
      uevent              = "DEVTYPE=scsi_host"
 
 
[root@lnxcstsdsggt02 hp_fibreutils]# ls -1c /sys/class/fc_host/host*/*_name 2> /dev/null | xargs -I {} grep -H -v "ZzZz" {} | sort
/sys/class/fc_host/host1/fabric_name:0x1000889471913c59
/sys/class/fc_host/host1/node_name:0x20000090fac12690
/sys/class/fc_host/host1/port_name:0x10000090fac12690
/sys/class/fc_host/host1/symbolic_name:Emulex AJ763B/AH403A FV2.10X6 DV12.0.0.13. HN:lnxcstsdsggt02.healthbc.org. OS:Linux
 
/sys/class/fc_host/host2/fabric_name:0x1000889471715586
/sys/class/fc_host/host2/node_name:0x20000090fac12691
/sys/class/fc_host/host2/port_name:0x10000090fac12691
/sys/class/fc_host/host2/symbolic_name:Emulex AJ763B/AH403A FV2.10X6 DV12.0.0.13. HN:lnxcstsdsggt02.healthbc.org. OS:Linux
[root@lnxcstsdsggt02 hp_fibreutils]#
 



mahsan@lnxpbcodb01 ~]$ su -
Password:
[root@lnxpbcodb01 ~]# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 2c:76:8a:d0:ee:f0 brd ff:ff:ff:ff:ff:ff
    inet 10.1.64.94/24 brd 10.1.64.255 scope global eth0
    inet6 fe80::2e76:8aff:fed0:eef0/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    link/ether 2c:76:8a:d0:ee:f1 brd ff:ff:ff:ff:ff:ff
4: sit0: <NOARP> mtu 1480 qdisc noop
    link/sit 0.0.0.0 brd 0.0.0.0
[root@lnxpbcodb01 ~]# ifconfig -a
eth0      Link encap:Ethernet  HWaddr 2C:76:8A:D0:EE:F0
          inet addr:10.1.64.94  Bcast:10.1.64.255  Mask:255.255.255.0
          inet6 addr: fe80::2e76:8aff:fed0:eef0/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3193357683 errors:0 dropped:609 overruns:0 frame:109
          TX packets:27289445250 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:235744550910 (219.5 GiB)  TX bytes:41163313479051 (37.4 TiB)
          Interrupt:169 Memory:fbaf0000-fbb00000

eth1      Link encap:Ethernet  HWaddr 2C:76:8A:D0:EE:F1
          BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 b)  TX bytes:0 (0.0 b)
          Interrupt:98 Memory:fbad0000-fbae0000

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:10619423 errors:0 dropped:0 overruns:0 frame:0
          TX packets:10619423 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:3519145823 (3.2 GiB)  TX bytes:3519145823 (3.2 GiB)

sit0      Link encap:IPv6-in-IPv4
          NOARP  MTU:1480  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 b)  TX bytes:0 (0.0 b)

[root@lnxpbcodb01 ~]# cd /etc/sysconfig/network-scripts/ifcfg-eth0
-bash: cd: /etc/sysconfig/network-scripts/ifcfg-eth0: Not a directory
[root@lnxpbcodb01 ~]# cd /etc/sysconfig/network-scripts/ifcfg-eth
ifcfg-eth0  ifcfg-eth1
[root@lnxpbcodb01 ~]# cd /etc/sysconfig/network-scripts/ifcfg-eth
ifcfg-eth0  ifcfg-eth1
[root@lnxpbcodb01 ~]# cd /etc/sysconfig/network-scripts/ifcfg-eth0
-bash: cd: /etc/sysconfig/network-scripts/ifcfg-eth0: Not a directory
[root@lnxpbcodb01 ~]# cat /etc/sysconfig/network-scripts/ifcfg-eth0
# Broadcom Corporation NetXtreme BCM5715 Gigabit Ethernet
DEVICE=eth0
BOOTPROTO=static
HWADDR=2C:76:8A:D0:EE:F0
IPADDR=10.1.64.94
NETMASK=255.255.255.0
ONBOOT=yes
TYPE=Ethernet
USERCTL=no
[root@lnxpbcodb01 ~]# cat /etc/sysconfig/network-scripts/ifcfg-eth1
# Broadcom Corporation NetXtreme BCM5715 Gigabit Ethernet
DEVICE=eth1
HWADDR=2C:76:8A:D0:EE:F1
ONBOOT=no
HOTPLUG=no
[root@lnxpbcodb01 ~]# ~]# ethtool -S eth1
-bash: ~]#: command not found
[root@lnxpbcodb01 ~]# ethtool -s ifcfg-eth0
[root@lnxpbcodb01 ~]# ethtool -s ifcfg-eth1
[root@lnxpbcodb01 ~]# ethtool -S ifcfg-eth1
Cannot get driver information: No such device
[root@lnxpbcodb01 ~]# ethtool -S ifcfg-eth1
Cannot get driver information: No such device
[root@lnxpbcodb01 ~]# ethtool -S eth0 | egrep -i "drop|ring|oob|discard
>
[root@lnxpbcodb01 ~]# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 2c:76:8a:d0:ee:f0 brd ff:ff:ff:ff:ff:ff
    inet 10.1.64.94/24 brd 10.1.64.255 scope global eth0
    inet6 fe80::2e76:8aff:fed0:eef0/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    link/ether 2c:76:8a:d0:ee:f1 brd ff:ff:ff:ff:ff:ff
4: sit0: <NOARP> mtu 1480 qdisc noop
    link/sit 0.0.0.0 brd 0.0.0.0
[root@lnxpbcodb01 ~]# ethtool -S eth0 | egrep -i "drop|ring|oob|discard"
     tx_discards: 0
     rx_discards: 609
     ring_set_send_prod_index: 0
     ring_status_update: 0
[root@lnxpbcodb01 ~]# ethtool -S eth0
NIC statistics:
     rx_octets: 235787390409
     rx_fragments: 0
     rx_ucast_packets: 3164451588
     rx_mcast_packets: 0
     rx_bcast_packets: 29564136
     rx_fcs_errors: 0
     rx_align_errors: 0
     rx_xon_pause_rcvd: 0
     rx_xoff_pause_rcvd: 0
     rx_mac_ctrl_rcvd: 0
     rx_xoff_entered: 0
     rx_frame_too_long_errors: 0
     rx_jabbers: 0
     rx_undersize_packets: 0
     rx_in_length_errors: 0
     rx_out_length_errors: 0
     rx_64_or_less_octet_packets: 0
     rx_65_to_127_octet_packets: 0
     rx_128_to_255_octet_packets: 0
     rx_256_to_511_octet_packets: 0
     rx_512_to_1023_octet_packets: 0
     rx_1024_to_1522_octet_packets: 0
     rx_1523_to_2047_octet_packets: 0
     rx_2048_to_4095_octet_packets: 0
     rx_4096_to_8191_octet_packets: 0
     rx_8192_to_9022_octet_packets: 0
     tx_octets: 41173240904742
     tx_collisions: 0
     tx_xon_sent: 0
     tx_xoff_sent: 0
     tx_flow_control: 0
     tx_mac_errors: 0
     tx_single_collisions: 0
     tx_mult_collisions: 0
     tx_deferred: 0
     tx_excessive_collisions: 0
     tx_late_collisions: 0
     tx_collide_2times: 0
     tx_collide_3times: 0
     tx_collide_4times: 0
     tx_collide_5times: 0
     tx_collide_6times: 0
     tx_collide_7times: 0
     tx_collide_8times: 0
     tx_collide_9times: 0
     tx_collide_10times: 0
     tx_collide_11times: 0
     tx_collide_12times: 0
     tx_collide_13times: 0
     tx_collide_14times: 0
     tx_collide_15times: 0
     tx_ucast_packets: 27295959667
     tx_mcast_packets: 34
     tx_bcast_packets: 40699
     tx_carrier_sense_errors: 0
     tx_discards: 0
     tx_errors: 0
     dma_writeq_full: 0
     dma_write_prioq_full: 0
     rxbds_empty: 109
     rx_discards: 609
     rx_errors: 0
     rx_threshold_hit: 0
     dma_readq_full: 0
     dma_read_prioq_full: 0
     tx_comp_queue_full: 0
     ring_set_send_prod_index: 0
     ring_status_update: 0
     nic_irqs: 0
     nic_avoided_irqs: 0
     nic_tx_threshold_hit: 0
     mbuf_lwm_thresh_hit: 0
[root@lnxpbcodb01 ~]# netstat -s
Ip:
    3175345875 total packets received
    0 forwarded
    0 incoming packets discarded
    3175345875 incoming packets delivered
    932727568 requests sent out
Icmp:
    887154 ICMP messages received
    11 input ICMP message failed.
    ICMP input histogram:
        destination unreachable: 518
        timeout in transit: 11
        echo requests: 886427
        echo replies: 7
        timestamp request: 191
    890172 ICMP messages sent
    0 ICMP messages failed
    ICMP output histogram:
        destination unreachable: 3551
        echo request: 7
        echo replies: 886423
        timestamp replies: 191
IcmpMsg:
        InType0: 7
        InType3: 518
        InType8: 886427
        InType11: 11
        InType13: 191
        OutType0: 886423
        OutType3: 3551
        OutType8: 7
        OutType14: 191
Tcp:
    2688172 active connections openings
    1695418 passive connection openings
    2533501 failed connection attempts
    68770 connection resets received
    189 connections established
    3170322532 segments received
    925137370 segments send out
    2970280 segments retransmited
    0 bad segments received.
    5778210 resets sent
Udp:
    3729121 packets received
    3746 packets to unknown port received.
    0 packet receive errors
    3729744 packets sent
TcpExt:
    1334201 invalid SYN cookies received
    3867 resets received for embryonic SYN_RECV sockets
    32 packets pruned from receive queue because of socket buffer overrun
    9 ICMP packets dropped because they were out-of-window
    92734 TCP sockets finished time wait in fast timer
    1 packets rejects in established connections because of timestamp
    1548561 delayed acks sent
    1016 delayed acks further delayed because of locked socket
    Quick ack mode was activated 39094 times
    220990475 packets directly queued to recvmsg prequeue.
    37639131 packets directly received from backlog
    22470177510 packets directly received from prequeue
    7566370 packets header predicted
    154862414 packets header predicted and directly queued to user
    1201655692 acknowledgments not containing data received
    1895850775 predicted acknowledgments
    70484 times recovered from packet loss due to SACK data
    Detected reordering 343 times using FACK
    Detected reordering 6115 times using SACK
    Detected reordering 13 times using time stamp
    6 congestion windows fully recovered
    17 congestion windows partially recovered using Hoe heuristic
    TCPDSACKUndo: 683
    32437 congestion windows recovered after partial ack
    2308802 TCP data loss events
    TCPLostRetransmit: 32
    3091 timeouts after SACK recovery
    21 timeouts in loss state
    2048957 fast retransmits
    777990 forward retransmits
    53373 retransmits in slow start
    76571 other TCP timeouts
    883 sack retransmits failed
    36260 times receiver scheduled too late for direct processing
    4341 packets collapsed in receive queue due to low socket buffer
    66688 DSACKs sent for old packets
    353866 DSACKs received
    439 DSACKs for out of order packets received
    43494 connections reset due to unexpected data
    240 connections reset due to early user close
    5048 connections aborted due to timeout
IpExt:
    InMcastPkts: 12
    OutMcastPkts: 14
    InBcastPkts: 403326
[root@lnxpbcodb01 ~]# ip -s -s link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    RX: bytes  packets  errors  dropped overrun mcast
    3519166311 10619547 0       0       0       0
    RX errors: length  crc     frame   fifo    missed
               0        0       0       0       0
    TX: bytes  packets  errors  dropped carrier collsns
    3519166311 10619547 0       0       0       0
    TX errors: aborted fifo    window  heartbeat
               0        0       0       0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 2c:76:8a:d0:ee:f0 brd ff:ff:ff:ff:ff:ff
    RX: bytes  packets  errors  dropped overrun mcast
    3878601040 3194319032 0       0       109     0
    RX errors: length  crc     frame   fifo    missed
               0        0       0       0       609
    TX: bytes  packets  errors  dropped carrier collsns
    2039269512 1529266373 0       0       0       0
    TX errors: aborted fifo    window  heartbeat
               0        0       0       0
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    link/ether 2c:76:8a:d0:ee:f1 brd ff:ff:ff:ff:ff:ff
    RX: bytes  packets  errors  dropped overrun mcast
    0          0        0       0       0       0
    RX errors: length  crc     frame   fifo    missed
               0        0       0       0       0
    TX: bytes  packets  errors  dropped carrier collsns
    0          0        0       0       0       0
    TX errors: aborted fifo    window  heartbeat
               0        0       0       0
4: sit0: <NOARP> mtu 1480 qdisc noop
    link/sit 0.0.0.0 brd 0.0.0.0
    RX: bytes  packets  errors  dropped overrun mcast
    0          0        0       0       0       0
    RX errors: length  crc     frame   fifo    missed
               0        0       0       0       0
    TX: bytes  packets  errors  dropped carrier collsns
    0          0        0       0       0       0
    TX errors: aborted fifo    window  heartbeat
               0        0       0       0
[root@lnxpbcodb01 ~]#














<pre>


