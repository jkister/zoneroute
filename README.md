# zoneroute

glibc NSS module that sends lookups for specific DNS zones straight to
chosen nameservers, bypassing resolv.conf, with no local resolver daemon.

## Why

`/etc/resolv.conf` can't say "send `corp.example.com` to this server and
everything else to that one".  The usual fixes are a local forwarder
(dnsmasq, unbound, dnscache) or systemd-resolved.  zoneroute does the
routing inside glibc's name service switch instead: no daemon, no cache,
no change to how any other name is resolved.

A common use is reverse DNS for RFC1918 addresses.  Public resolvers
won't answer `*.168.192.in-addr.arpa`, so syslog and anything else
calling `getnameinfo()` shows bare IPs even when your own authoritative
server has the PTR records.

## How it works

With `hosts: files zoneroute dns` in `/etc/nsswitch.conf`, every
`getaddrinfo()`, `getnameinfo()`, `gethostbyname()` and `gethostbyaddr()`
call passes through the module:

- If the name (or the `in-addr.arpa` / `ip6.arpa` name of the address)
  is in a configured zone, the module queries that zone's nameservers
  directly and returns the answer.
- Otherwise it returns "not found" immediately, without touching the
  network, and glibc moves on to `dns` as usual.
- If the zone's nameservers don't respond (1 second per server), the
  module steps aside and `dns` gets a turn.

The config is read on every lookup, so edits take effect immediately.

## Build and install

Needs gcc and the glibc headers (`build-essential` on Debian).

```sh
make
sudo make install          # /usr/local/lib/libnss_zoneroute.so.2, runs ldconfig
sudo cp eg/nss-zoneroute.conf /etc/nss-zoneroute.conf
sudo vi /etc/nss-zoneroute.conf
```

Then add `zoneroute` to the `hosts:` line of `/etc/nsswitch.conf`,
after `files` and before `dns`:

```
hosts:          files zoneroute dns
```

Check it with `getent`, which goes through NSS:

```sh
getent hosts 192.168.2.16          # reverse
getent hosts host.corp.example.com # forward
```

## Configuration

`/etc/nss-zoneroute.conf` holds one or more `{ }` blocks.  Each block
lists nameservers and the zones they answer for:

```
{
    // LAN reverse lookups
    nameserver 192.168.1.53
    nameserver 192.0.2.53          # off-site secondary

    zone 1.168.192.in-addr.arpa
    zone 2.168.192.in-addr.arpa
},
{
    nameserver 198.51.100.10
    zone lab.corp.example.com
}
```

- `#` and `//` start comments; commas between blocks are optional.
- Lines outside any block form one more block, so a flat list of
  `nameserver` / `zone` lines also works.
- When zones in different blocks match, the longest (most specific)
  zone wins.  If the same zone is in two blocks, the first wins; blocks
  are not fallbacks for each other, so put backup servers in the same
  block.
- Limits: 16 blocks, 64 zones, 3 nameservers per block.
- `NSS_ZONEROUTE_CONF=/path` overrides the config file (ignored for
  setuid programs), which is handy for testing.

See [eg/nss-zoneroute.conf](eg/nss-zoneroute.conf) for a commented
example.

## Caveats

- **List zones exactly as the server serves them.**  Some servers
  (tinydns, for one) silently ignore queries outside their zones.  If
  you configure `168.192.in-addr.arpa` but the server only serves
  `2.168.192.in-addr.arpa`, every lookup for an unserved address waits
  for the timeout instead of failing quickly.  Check with
  `dig SOA 2.168.192.in-addr.arpa @server`.
- **Nameservers must be IPv4 addresses.**  Queries for IPv6 data (AAAA,
  `ip6.arpa`) work, but the servers themselves are reached over IPv4.
  The module uses glibc's resolver to send queries, and glibc only
  exposes IPv4 nameservers through its public interface.  IPv6
  `nameserver` lines are ignored.
- **`host`, `dig` and `nslookup` don't use NSS**, so they ignore this
  module.  Use `getent hosts` to see what programs actually get, or
  point the tool at the server: `dig -x 192.168.2.16 @192.168.1.53`.
- **Running programs keep the library they loaded.**  After
  reinstalling, restart long-running daemons to pick up new code.  The
  config file is re-read on every lookup and needs no restart.
- Programs that cache lookups themselves (rsyslog, nscd) may need a
  restart after zone changes.
- Every program on the host uses this module.  If a zone's servers are
  down, lookups in that zone take up to 1 second per server before
  falling through to `dns`.

## Testing without installing

A test program can switch its own `hosts` lookup order with
`__nss_configure_lookup()` and load the module from the build
directory, leaving the system untouched:

```c
#include <nss.h>
...
__nss_configure_lookup("hosts", "zoneroute dns");
```

```sh
LD_LIBRARY_PATH=. NSS_ZONEROUTE_CONF=eg/nss-zoneroute.conf ./mytest
```

## Uninstall

Remove `zoneroute` from `/etc/nsswitch.conf`, then delete
`/usr/local/lib/libnss_zoneroute.so.2` and `/etc/nss-zoneroute.conf`
and run `ldconfig`.

## License

Apache License 2.0; see [LICENSE](LICENSE).
