#!/usr/bin/env -S nix eval --raw --impure -f
let
  pkgs = import <nixpkgs> { };
  inherit (pkgs) callPackage lib;
  config = (callPackage ./. { }).config;
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

builtins.toJSON (evalRuleset (ruleset {
  filter = table { family = families.netdev; } {
    ingress_common = with tcpFlags; chain 
      [(is.eq (op."&" tcp.flags (fin + syn)) (fin + syn)) drop]
      [(is.eq (op."&" tcp.flags (op."&" syn rst)) (op."&" syn rst)) drop]
      [(is.eq (op."&" tcp.flags (op."&" [ fin syn rst psh ack urg ])) 0) drop]
      [(is.in' tcp.flags syn) (is.eq tcpOpt.maxseg.size (range 0 500)) drop]
      [(is.eq ip.saddr "127.0.0.1") drop]
      [(is.eq ip6.saddr "::1") drop]
      [(is.eq (fib (with fibFlags; [ saddr iif ]) fibResults.oif) missing) drop]
      [return];

    ingress_lan = chain { type = chainTypes.filter; hook = hooks.ingress; dev = "lan0"; prio = -500; policy = chainPolicies.accept; }
      [(jump "ingress_common")];

    ingress_wan = with fibAddrTypes; chain { type = chainTypes.filter; hook = hooks.ingress; dev = "wan0"; prio = -500; policy = chainPolicies.drop; }
      [(jump "ingress_common")]
      [(is.ne (fib (with fibFlags; [ daddr iif ]) fibResults.type) (set' [ local broadcast multicast ])) drop]
      [(is.eq ip.protocol (set' [ local broadcast multicast ])) drop]
      [(is.eq ip.protocol "icmp") (is.eq icmp.type (with icmpTypes; set' [ info-request address-mask-request router-advertisement router-solicitation redirect ])) drop]
      [(is.eq ip6.nexthdr "icmpv6") (is.eq icmpv6.type (with icmpv6Types; set' [ mld-listener-query mld-listener-report mld-listener-reduction nd-router-solicit nd-router-advert nd-redirect router-renumbering ])) drop]
      [(is.eq ip.protocol "icmp") (limit' { rate = 20; per = timeUnits.second; }) accept]
      [(is.eq ip6.nexthdr "icmpv6") (limit' { rate = 20; per = timeUnits.second; }) accept]
      [(is.eq ip.protocol "icmp") drop]
      [(is.eq ip6.nexthdr "icmpv6") drop]
      [(is.eq ip.protocol (set' [ "tcp" "udp" ])) (is.eq th.dport (set' [ 22 53 80 443 853 ])) accept]
      [(is.eq ip6.nexthdr (set' [ "tcp" "udp" ])) (is.eq th.dport (set' [ 22 53 80 443 853 ])) accept];
  };
  global = table { family = families.inet; } {
    inbound_wan = chain
      [(is.eq ip.protocol inetProtos.icmp) (is.ne icmp.type (with icmpTypes; set' [ destination-unreachable echo-request time-exceeded parameter-problem ])) drop]
      [(is.eq ip6.nexthdr inetProtos.ipv6-icmp) (is.ne icmpv6.type (with icmpv6Types; set' [ destination-unreachable echo-request time-exceeded parameter-problem packet-too-big nd-neighbor-solicit ])) drop]
      # using strings instead of constants is of course possible
      [(is.eq ip.protocol "icmp") accept]
      [(is.eq ip6.nexthdr "icmpv6") accept]
      [(is.eq th.dport 22) accept];
    inbound_lan = chain
      [accept];
    inbound = chain { type = chainTypes.filter; hook = hooks.input; prio = 0; policy = chainPolicies.drop; }
      [(vmap ct.state { established = accept; related = accept; invalid = drop; })]
      [(is.eq (op."&" tcp.flags tcpFlags.syn) 0) (is.eq ct.state ctStates.new) drop]
      [(vmap meta.iifname { lo = accept; wan0 = jump "inbound_wan"; lan0 = jump "inbound_lan"; })];
    forward = chain { type = chainTypes.filter; hook = hooks.forward; prio = 0; policy = chainPolicies.drop; }
      [(vmap ct.state { established = accept; related = accept; invalid = drop; })]
      [(is.eq meta.iifname "wan0") (is.eq meta.oifname "lan0") accept]
      [(is.eq meta.iifname "lan0") accept]
      [(is.eq meta.iifname "wan0") (is.eq meta.oifname "wan0") accept];
    postrouting = chain { type = chainTypes.nat; hook = hooks.postrouting; prio = 0; policy = chainPolicies.accept; }
      [(is.eq meta.protocol (with etherTypes; set' [ ip ip6 ])) (is.eq meta.iifname "lan0") (is.eq meta.oifname "wan0") masquerade];
    block4 = set { type = nftTypes.ipv4_addr; flags = with setFlags; [ interval ]; } [
      (cidr "194.190.137.0" 24)
      (cidr "194.190.157.0" 24)
      (cidr "194.190.21.0" 24)
      (cidr "194.226.130.0" 23)
    ];
    block6 = set { type = nftTypes.ipv6_addr; flags = with setFlags; [ interval ]; };
    force_unvpn4 = set { type = nftTypes.ipv4_addr; flags = with setFlags; [ interval ]; };
    force_unvpn6 = set { type = nftTypes.ipv6_addr; flags = with setFlags; [ interval ]; };
    prerouting = chain { type = chainTypes.filter; hook = hooks.prerouting; prio = 0; policy = chainPolicies.accept; }
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
