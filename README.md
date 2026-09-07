# SSH Brute-Force Detection & Automated IP Blocking System

A Bash-based defensive security tool that monitors SSH authentication logs, detects repeated failed login attempts, generates alerts, and automatically blocks suspicious IP addresses using `iptables` and `ip6tables`.

## Features

* Real-time SSH authentication log monitoring
* Detects repeated failed SSH password attempts
* Tracks attempts by source IP address
* Supports IPv4 and IPv6
* Alert after 5 failed attempts
* Automatic IP blocking after 10 failed attempts
* 10-minute detection window
* Supports multiple SSH log sources:

  * `/var/log/auth.log`
  * `/var/log/secure`
  * `systemd journal`
* Saves detected attacks to `flagged_ips.txt`
* Manual IP unblocking
* Duplicate alert prevention
* Uses `iptables` for IPv4 blocking
* Uses `ip6tables` for IPv6 blocking

## Detection Logic

The tool uses a sliding time window to count failed SSH authentication attempts from each source IP.

```text
5 failed attempts within 10 minutes
        ↓
Generate Security Alert
```

```text
10 failed attempts within 10 minutes
        ↓
Generate Security Alert
        ↓
Automatically Block Source IP
```

## Technologies Used

* Bash
* Linux
* OpenSSH
* iptables
* ip6tables
* systemd journal
* Hydra (for authorized lab testing)

## Requirements

* Linux operating system
* Bash
* OpenSSH
* `iptables`
* `ip6tables` for IPv6 blocking
* `sudo` privileges

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/ssh-bruteforce-detection-system.git
```

Enter the project directory:

```bash
cd ssh-bruteforce-detection-system
```

Make the script executable:

```bash
chmod +x ssh-bruteforce-detection.sh
```

## Usage

Start the detection system:

```bash
sudo ./ssh-bruteforce-detection.sh
```

### Custom Alert Threshold

For example, alert after 3 failed attempts:

```bash
sudo ./ssh-bruteforce-detection.sh -t 3
```

### Custom Detection Window

For example, use a 5-minute window:

```bash
sudo ./ssh-bruteforce-detection.sh -w 5
```

### Unblock an IP Address

IPv4:

```bash
sudo ./ssh-bruteforce-detection.sh -u 192.168.1.20
```

IPv6:

```bash
sudo ./ssh-bruteforce-detection.sh -u 2001:db8::20
```

### Display Help

```bash
sudo ./ssh-bruteforce-detection.sh -h
```

## Testing

The project can be tested in an isolated and authorized lab environment.

A second VM can be used to simulate SSH brute-force attempts with Hydra, while the first VM runs the detection system.

Example:

```bash
hydra -t 1 -l testuser -P test-passwords.txt ssh://<TARGET-IP>
```

The detector should identify the failed attempts and generate an alert.

At the configured blocking threshold, the source IP is automatically added to the firewall.

## Firewall Verification

Check IPv4 blocked addresses:

```bash
sudo iptables -L INPUT -n --line-numbers
```

Check IPv6 blocked addresses:

```bash
sudo ip6tables -L INPUT -n --line-numbers
```

Example:

```text
Chain INPUT (policy ACCEPT)

num  target  prot opt source          destination
1    DROP    all  --  192.168.1.35    0.0.0.0/0
```

## Output

Detected attacks are recorded in:

```text
flagged_ips.txt
```

Example:

```text
2026-09-05 23:39:14 | IP: 192.168.1.35 | Attempts: 5 | Possible SSH Brute-Force
```

## Project Workflow

```text
SSH Authentication Attempts
            ↓
       SSH Log Source
            ↓
      Log Monitoring
            ↓
     Extract Source IP
            ↓
   Count Failed Attempts
            ↓
    ┌───────┴────────┐
    ↓                ↓
 5 Attempts       10 Attempts
    ↓                ↓
   Alert        Alert + Block
                     ↓
              iptables/ip6tables
```

## Security Considerations

* Run the tool only with appropriate authorization.
* Test brute-force simulation only against systems you own or are authorized to test.
* Do not upload passwords, private keys, or sensitive authentication logs to GitHub.
* The tool intentionally does not block `127.0.0.1` or `::1` to prevent accidental local lockout.

## Limitations

* Detection is based primarily on failed password authentication log entries.
* Distributed brute-force attacks using many source IPs may evade simple per-IP thresholds.
* No database or persistent detection state is currently implemented.
* No email, Telegram, or SIEM notification integration.
* No web-based dashboard.

## Future Enhancements

* Email and Telegram notifications
* SIEM integration
* Web dashboard
* Persistent attack history
* GeoIP-based analysis
* Distributed brute-force detection
* Automatic temporary blocking and expiration
* Fail2Ban integration

## Disclaimer

This project is intended for **defensive security research, learning, and authorized laboratory testing only**.
