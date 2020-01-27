# DockerSniff

## Summary

DockerSniff is a dockerized wpa capture device

## Dependencies

Docker

## Setup

```bash
git clone https://github.com/wamacdonald89/dockersniff.git
```

## Run

Arguments:

**-i | --interface <interface>** (required)

**-c | --channel** <ch#>

**-h** help

**-v** Version

```bash
sudo ./dockersniff -i <interface> -c <channel> 
```

## Notes

Requires pyrit and a prebuilt pyrit sqlite database labeled pyrit.db in /pyrit/
Will update to allow specifying database in command
