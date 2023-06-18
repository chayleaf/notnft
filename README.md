# Not Nft

This is a partly-typed version of nftables's JSON format for Nix (it
checks JSON structure and expression contexts; it doesn't check the
types themselves). It uses nixpkgs's option system, which means it can
integrate with Nix very well. A DSL is provided to write JSON nftables
with more safety and convenience, but you can alternatively simply
directly follow the official schema if you're more comfortable with
that.

nftables' documentation is *really* poor, so to the extent possible I
collected personal internal documentation in [NOTES.md](./NOTES.md). The
most important thing is not to rely on the official documentation for
~~anything~~ obscure bits (it's fine for the common use cases, but in
general you really can't trust it). I'll try to push some documentation
changes upstream.

- Q: How can I quickly test it?
- A: Clone this repo and edit/run `./sample.nix`
- Q: Why?
- A: I'm working on a fresh NixOS router config, and wanted to nixify
  the nftables syntax. Since this project uses nixpkgs's module system,
  I can easily add options that directly map to nftables concepts.
- Q: Is this limited in any way?
- A: I fully support the current JSON specification... no, I refuse to
  call it a specification - I fully support whatever JSON parsing code
  there is in nftables, but the nftables DSL has a different feature set
  compared to the JSON API (some features are only present in the
  former, some only in the latter). I might add a compiler to .nft files
  some day.
- Q: Why the name?
- A: I already created [notlua](https://github.com/chayleaf/notlua), so
  this is the next project in that "series".
- Q: Does this have any relation to Non-Fungible Tokens?
- A: As the name implies, no.
- Q: What license is this available under?
- A: GPL2.0-or-later, same as nftables (some parts of nftables are GPL2
  only though).

## Example using the "fancy" DSL

```nix
with notnft.dsl; with payload; ruleset {
  # nftables has a loooot of enums. You can access them directly (e.g.
  # notnft.families.netdev), but it really is hard to remember them all.
  # While the nftables dsl just dynamically figures out what you wanted
  # to say, I tried to implement the same logic, but to pass the info
  # back to the user I have to use lambdas.
  # Of course, you can simply use strings instead (e.g. "netdev"), but
  # that way you won't be aware of typos/wrongly used values.
  filter = add table { family = f: f.netdev; } {
    # chains are created by adding lists of statements to them, one list
    # for each rule. You can alternatively pass a list of lists, in that
    # case each sub-list will be considered a separate rule.
    ingress_common = add chain 
      # is.eq is an alias for the match statement with the == operator
      # payload.tcp.flags is the same as "tcp flags" in nftables
      # language, and accesses the field "flags" of "tcp" payload
      [(is.eq (bit.and tcp.flags (f: bit.or f.fin f.syn)) (f: bit.or f.fin f.syn)) drop]
      [(is.eq (bit.and tcp.flags (f: bit.or f.syn f.rst)) (f: bit.or f.syn f.rst)) drop]
      [(is.eq (bit.and tcp.flags (f: with f; bit.or fin syn rst psh ack urg)) 0) drop]
      # In the nftables language, you often see stuff like
      # "tcp flags syn" to check if syn is set in tcp flags, not using
      # any operator between the two values. The same logic is available
      # in notnft via "is.auto" (or "is.au") for automatically inferring
      # the operation.
      # tcpOpt is for getting the value of a tcp option field
      # (or checking for presence of a tcp option)
      [(is.auto tcp.flags (f: f.syn)) (is.eq tcpOpt.maxseg.size (range 0 500)) drop]
      [(is.eq ip.saddr "127.0.0.1") drop]
      [(is.eq ip6.saddr "::1") drop]
      [(is.eq (fib (f: with f; [ saddr iif ]) (f: f.oif)) missing) drop]
      [return];

    ingress_lan = add chain { type = f: f.filter; hook = f: f.ingress; dev = "lan0"; prio = -500; policy = f: f.accept; }
      [(jump "ingress_common")];

    ingress_wan = add chain { type = f: f.filter; hook = f: f.ingress; dev = "wan0"; prio = -500; policy = f: f.drop; }
      [(jump "ingress_common")]
      # in nftables language, anonymous sets are used quite often via
      # the syntax { a, b, c }. Here you have to create them using "set"
      [(is.ne (fib (f: with f; [ daddr iif ]) (f: f.type)) (f: with f; set [ local broadcast multicast ])) drop]
      [(is.eq ip.protocol (f: f.icmp)) (is.eq icmp.type (f: with f; set [ info-request address-mask-request router-advertisement router-solicitation redirect ])) drop]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) (is.eq icmpv6.type (f: with f; set [ mld-listener-query mld-listener-report mld-listener-reduction nd-router-solicit nd-router-advert nd-redirect router-renumbering ])) drop]
      [(is.eq ip.protocol (f: f.icmp)) (limit { rate = 20; per = f: f.second; }) accept]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) (limit { rate = 20; per = f: f.second; }) accept]
      [(is.eq ip.protocol (f: f.icmp)) drop]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) drop]
      [(is.eq ip.protocol (f: with f; set [ tcp udp ])) (is.eq th.dport (set [ 22 53 80 443 853 ])) accept]
      [(is.eq ip6.nexthdr (f: with f; set [ tcp udp ])) (is.eq th.dport (set [ 22 53 80 443 853 ])) accept];
  };

  global = add table { family = f: f.inet; } {
    inbound_wan = add chain
      [(is.eq ip.protocol (f: f.icmp)) (is.ne icmp.type (f: with f; set [ destination-unreachable echo-request time-exceeded parameter-problem ])) drop]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) (is.ne icmpv6.type (f: with f; set [ destination-unreachable echo-request time-exceeded parameter-problem packet-too-big nd-neighbor-solicit ])) drop]
      [(is.eq ip.protocol (f: f.icmp)) accept]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) accept]
      [(is.eq th.dport 22) accept];

    inbound_lan = add chain
      [accept];

    inbound = add chain { type = f: f.filter; hook = f: f.input; prio = f: f.filter; policy = f: f.drop; }
      [(vmap ct.state { established = accept; related = accept; invalid = drop; })]
      [(is.eq (bit.and tcp.flags (f: f.syn)) 0) (is.eq ct.state (f: f.new)) drop]
      [(vmap meta.iifname { lo = accept; wan0 = jump "inbound_wan"; lan0 = jump "inbound_lan"; })];

    forward = add chain { type = f: f.filter; hook = f: f.forward; prio = f: f.filter; policy = f: f.drop; }
      [(vmap ct.state { established = accept; related = accept; invalid = drop; })]
      [(is.eq meta.iifname "wan0") (is.eq meta.oifname "lan0") accept]
      [(is.eq meta.iifname "lan0") accept]
      [(is.eq meta.iifname "wan0") (is.eq meta.oifname "wan0") accept];

    postrouting = add chain { type = f: f.nat; hook = f: f.postrouting; prio = f: f.filter; policy = f: f.accept; }
      [(is.eq meta.protocol (f: with f; set [ ip ip6 ])) (is.eq meta.iifname "lan0") (is.eq meta.oifname "wan0") masquerade];

    block4 = add set { type = f: f.ipv4_addr; flags = f: with f; [ interval ]; } [
      (cidr "194.190.137.0" 24)
      (cidr "194.190.157.0" 24)
      (cidr "194.190.21.0" 24)
      (cidr "194.226.130.0" 23)
    ];

    block6 = add set { type = f: f.ipv6_addr; flags = f: with f; [ interval ]; };

    force_unvpn4 = add set { type = f: f.ipv4_addr; flags = f: with f; [ interval ]; };

    force_unvpn6 = add set { type = f: f.ipv6_addr; flags = f: with f; [ interval ]; };

    prerouting = add chain { type = f: f.filter; hook = f: f.prerouting; prio = f: f.filter; policy = f: f.accept; }
      # mangle means "set A to B", the nftables language analog to the
      # following would be "meta mark set ct mark"
      [(mangle meta.mark ct.mark)]
      [(is.ne meta.mark 0) accept]
      [(is.eq meta.iifname "lan0") (mangle meta.mark 2)]
      # you can access named sets via "@set_name"
      [(is.eq ip.daddr "@force_unvpn4") (mangle meta.mark 1)]
      [(is.eq ip6.daddr "@force_unvpn6") (mangle meta.mark 1)]
      [(is.eq ip.daddr "@block4") drop]
      [(is.eq ip6.daddr "@block6") drop]
      [(mangle ct.mark meta.mark)];
  };
}
```

You can use `add existing chain` or `add existing table` if you want to
extend an existing chain/table without issuing a command for creating
it.
