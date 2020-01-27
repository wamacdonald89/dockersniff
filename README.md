# DockerWIFI

## Summary

DockerWIFI is a dockerized hostapd/dhcp/iptables bundle that makes setting up and deploying software-based access points (APs) easy. 

## Dependencies

Docker

## Setup

```bash
git clone https://github.com/wamacdonald89/dockerwifi.git
```

## Run

Arguments:

**-i | --interface <interface>** (required)

**-c | --channel** <ch#>

**--passphrase** <passphrase>

**--ssid <AP Name>**

**--config** <hostapd.conf>

**-h** help

**-v** Version

```bash
sudo ./dockerwifi -i <interface> -c 36 --ssid dockerwifi --passphrase dockerwifi 
```

## Notes

- Currently only supports WPA2 networks but is fully configurable by modifying the config/default.conf file as you would hostapd.conf
- Note: Network services may interfere with dockerwifi. It is suggested to disable services like Network-Manager it becomes an issue.

