#!/usr/bin/env -S nix eval --raw --impure -f
let
  pkgs = import <nixpkgs> { };
  inherit (pkgs) callPackage lib;
  config = (callPackage ./. {
    config.notnft.dslAllowFunctors = false;
  }).config;
  inherit (config) notnft;
  evalRuleset = val: (lib.modules.evalModules {
    modules = [ {
      config.val = val;
      options.val = lib.mkOption { type = notnft.types.ruleset; };
    } ];
  }).config.val;

  inherit (notnft) dsl;
in
with notnft; with dsl; with dsl.payload;

builtins.toJSON (evalRuleset (Ruleset {
  filter = Table { family = f: f.netdev; } {
    ingress_common = Chain 
      [(is.eq (op."&" tcp.flags (f: op."|" f.fin f.syn)) (f: op."|" f.fin f.syn)) drop]
      [(is.eq (op."&" tcp.flags (f: op."|" f.syn f.rst)) (f: op."|" f.syn f.rst)) drop]
      [(is.eq (op."&" tcp.flags (f: with f; op."|" [ fin syn rst psh ack urg ])) 0) drop]
      [(is.auto tcp.flags (f: f.syn)) (is.eq tcpOpt.maxseg.size (range 0 500)) drop]
      [(is.eq ip.saddr "127.0.0.1") drop]
      [(is.eq ip6.saddr "::1") drop]
      [(is.eq (fib (f: with f; [ saddr iif ]) (f: f.oif)) missing) drop]
      [return];

    ingress_lan = Chain { type = f: f.filter; hook = f: f.ingress; dev = "lan0"; prio = -500; policy = f: f.accept; }
      [(jump "ingress_common")];

    ingress_wan = Chain { type = f: f.filter; hook = f: f.ingress; dev = "wan0"; prio = -500; policy = f: f.drop; }
      [(jump "ingress_common")]
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
  global = Table { family = f: f.inet; } {
    inbound_wan = Chain
      [(is.eq ip.protocol (f: f.icmp)) (is.ne icmp.type (f: with f; set [ destination-unreachable echo-request time-exceeded parameter-problem ])) drop]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) (is.ne icmpv6.type (f: with f; set [ destination-unreachable echo-request time-exceeded parameter-problem packet-too-big nd-neighbor-solicit ])) drop]
      [(is.eq ip.protocol (f: f.icmp)) accept]
      [(is.eq ip6.nexthdr (f: f.ipv6-icmp)) accept]
      [(is.eq th.dport 22) accept];
    inbound_lan = Chain
      [accept];
    inbound = Chain { type = f: f.filter; hook = f: f.input; prio = f: f.filter; policy = f: f.drop; }
      [(vmap ct.state { established = accept; related = accept; invalid = drop; })]
      [(is.eq (op."&" tcp.flags (f: f.syn)) 0) (is.eq ct.state (f: f.new)) drop]
      [(vmap meta.iifname { lo = accept; wan0 = jump "inbound_wan"; lan0 = jump "inbound_lan"; })];
    forward = Chain { type = f: f.filter; hook = f: f.forward; prio = f: f.filter; policy = f: f.drop; }
      [(vmap ct.state { established = accept; related = accept; invalid = drop; })]
      [(is.eq meta.iifname "wan0") (is.eq meta.oifname "lan0") accept]
      [(is.eq meta.iifname "lan0") accept]
      [(is.eq meta.iifname "wan0") (is.eq meta.oifname "wan0") accept];
    postrouting = Chain { type = f: f.nat; hook = f: f.postrouting; prio = f: f.filter; policy = f: f.accept; }
      [(is.eq meta.protocol (f: with f; set [ ip ip6 ])) (is.eq meta.iifname "lan0") (is.eq meta.oifname "wan0") masquerade];
    block4 = Set { type = f: f.ipv4_addr; flags = f: with f; [ interval ]; } [
      (cidr "194.190.137.0" 24)
      (cidr "194.190.157.0" 24)
      (cidr "194.190.21.0" 24)
      (cidr "194.226.130.0" 23)
    ];
    block6 = Set { type = f: f.ipv6_addr; flags = f: with f; [ interval ]; };
    force_unvpn4 = Set { type = f: f.ipv4_addr; flags = f: with f; [ interval ]; };
    force_unvpn6 = Set { type = f: f.ipv6_addr; flags = f: with f; [ interval ]; };
    prerouting = Chain { type = f: f.filter; hook = f: f.prerouting; prio = f: f.filter; policy = f: f.accept; }
      [(mangle meta.mark ct.mark)]
      [(is.ne meta.mark 0) accept]
      [(is.eq meta.iifname "lan0") (mangle meta.mark 2)]
      [(is.eq ip.daddr "@force_unvpn4") (mangle meta.mark 1)]
      [(is.eq ip6.daddr "@force_unvpn6") (mangle meta.mark 1)]
      [(is.eq ip.daddr "@block4") drop]
      [(is.eq ip6.daddr "@block6") drop]
      [(mangle ct.mark meta.mark)];
  };
}))
