# Netcider v2.0 Beta
Calculates network segments based on CIDR notation.

It's a pretty handy utility for pen testers.

You provide a CIDR range and this tool will output network statistics, or the complete IP range, which can then be fed to tools that don't support CIDR notation.

```
──────────────────────────── Netcider v2.0 Beta ────────────────────────────
Author      :  Shawn Evans (sevans@nopsec.com)
Constributor:  Jan Gebser  (github@brainhub24.com)

Options:
-o      Output full IP range to stdout

Example:
$ python netCider.py 192.168.0.2/24
$ python netCider.py -o 192.168.0.2/24
```
