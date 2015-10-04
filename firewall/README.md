# Iptables and Ebtables Firewall Modules

Iptables is a generic table structure for the definition of rulesets.

![alt text](http://4.bp.blogspot.com/-sahyhu3TFeI/T4RlHrtBofI/AAAAAAAACD8/VIwGKBG2cfc/s1600/f-firestarter-firewall.png "Logo Title Text 1")
Source: [Mekey Salaria](http://crackedtownship.blogspot.de/2012/04/how-to-install-firewall-in-ubuntu-linux.html)

These rulesets has been written for a desktop client, bridge server and Ubuntu Phone. They're basic scripte and they must to get filled with your personal rules. The Ubuntu Firewall script for `ubuntu touch` or `ubuntu phone` has been written for the [BQ Aquaris Phone Ubuntu Edition](http://www.ubuntu.com/phone/devices).

| Kernel Module |  Userspace Tool's | Script Description |
| :-------------: | :----------------------: | :------------------: |
| ip_tables     | [iptables](http://git.netfilter.org/ebtables/) | [desktop firewall](https://github.com/hinzigers/script/blob/master/firewall/basis-script) and [mobile firewall](https://github.com/hinzigers/script/blob/master/firewall/basis-script.ubuntu-phone) |
| ip6_tables    | ip6tables | |
| arp_tables    | [arptables](http://git.netfilter.org/arptables/) | |
| ebtables      | [ebtables](http://ebtables.netfilter.org/) | [bridge firewall](https://github.com/hinzigers/script/blob/master/firewall/basis-script-bridge) |

Make directory `firewall` in `/etc/` and put all directories and all lists into, if you want. Copy the firewall script into `/etc/init.d/`and  make symlink from `/etc/init.d/firewall` to `/etc/firewall/firewall`. Change the attribute `chmod u=rwx "firewall" | chmod g-r "firewall" | chmod o-r "firewall"` to `444`.

### Firewall Start

The script will automatically detect the network variable and sets this also equal. The script starts only reliably with one enabled interface (wlan0 or ccmni0).

The firewall is started with `service fw start`.

![alt text](https://github.com/hinzigers/script/blob/master/images/firewall_start.png "Firewall Start 1")

Started by ssh console.

![alt text](https://github.com/hinzigers/script/blob/master/images/firewall_start2.png "Firewall Start 2")

Started from the smart phone witch Wi-Fi.

![alt text](https://github.com/hinzigers/script/blob/master/images/firewall_start3.png "Firewall Start 3")

Started from the smart phone witch SIM.
