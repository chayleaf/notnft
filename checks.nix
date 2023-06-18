{ flake, lib, ... }:

let
  inherit (flake) types dsl;
  inherit (lib.modules) evalModules;
  # check that `expr` is of type `type`, and that the merged value equals `expected`
  # if `json` is true, compare jsons
  chkTypeEq' = json: type: expected: expr:
    let val = (evalModules {
    modules = [
      {
        options.val = lib.mkOption {
          inherit type;
        };
        config.val = expr;
      }
    ];
  }).config.val;
  in
    # assert lib.assertMsg val.success "Invalid type for ${builtins.toJSON expr}";
    lib.assertMsg (if json then builtins.toJSON val == builtins.toJSON expected else val == expected) "Invalid value for ${builtins.toJSON expr} (got ${builtins.toJSON val}, expected ${builtins.toJSON expected})";
  chkTypeEq = chkTypeEq' false;
  chkTypeJson' = chkTypeEq' true;
  # check that `x` is an expression and the merged value equals `x`
  chkExpr = x: chkTypeEq types.expression x x;
  chkTypeJson = type: x: lib.trace (builtins.toJSON x) chkTypeJson' type x x;
  # check that `x` is an expression and the merged value equals `x` when both are converted to json
  # how this is used: enum values in notnft have a __tostring attr, which automatically gets called
  # by toJSON. This means that despite merging to a different value (string rather than opaque enum),
  # values are still considered equal.
  chkExprJson = chkTypeJson types.expression;
  # check that the second arg is an expression and the merged value equals the first arg
  chkExprEq = chkTypeEq types.expression;
  # check that evaluation of `x` fails
  fails = x: !(builtins.tryEval x).success;

  chkCommand = x: chkTypeEq' true types.command x x;
  removeAll = attrs: builtins.mapAttrs (k: v: builtins.removeAttrs v attrs);
  addAll = attrs: builtins.mapAttrs (k: v: v // attrs);
  preserveAll = attrs: builtins.mapAttrs (k: lib.filterAttrs (k: v: builtins.elem k attrs));
  chkAdd = x:
    assert chkCommand { add = x; };
    chkCommand { create = x; };
  chkAddNoDelete = x:
    assert chkAdd x;
    assert fails (chkDelete x);
    fails (chkDelete (addAll { handle = 5; } x));
  chkDelete = x: chkCommand { delete = x; };
  fieldsRequired = fields: func: x: assert func x; builtins.all (field: fails (func (removeAll [ field ] x))) fields;
  # fieldsOptional = fields: func: x: assert func x; builtins.all (field: func (removeAll [ field ] x)) fields;
  chkAddDelete = x:
    assert chkAdd x;
    assert chkDelete x;
    assert chkDelete (addAll { handle = 5; } (removeAll [ "name" ] x));
    assert chkDelete (addAll { handle = 5; } (preserveAll [ "table" "family" "chain" ] x));
    assert fails (chkDelete (removeAll [ "name" ] x));
    fails (chkDelete (removeAll [ "name" ] x));

in

### EXPRESSIONS
# primitives
assert chkExpr "";
assert chkExpr "abcd";
assert chkExpr "@abcd"; # set reference
assert chkExpr "\\*"; # wildcard
assert chkExpr 5;
assert chkExpr false;
assert chkExpr true;
assert chkExpr [ ];
assert chkExpr [ 1 2 3 ];
# concat expr
assert chkExpr { concat = []; };
# set expr
assert chkExpr { set = 5; };
assert chkExpr { set = [ ]; };
assert chkExpr { set = [ 1 2 3 ]; };
# map expr
assert chkExpr { map = { key = 1; data = 2; }; };
assert fails (chkExpr { map = { key = 1; data = null; }; });
# prefix expr
assert chkExpr { prefix = { addr = "127.0.0.0"; len = 8; }; };
# range expr
assert chkExpr { range = [ 1 2 ]; };
assert chkExprEq { range = [ 1 2 ]; } { range = { min = 1; max = 2; }; };
assert fails (chkExpr { range = [ 1 ]; });
assert fails (chkExpr { range = [ 1 2 3 ]; });
# payload expr
assert chkExpr { payload = { base = "ll"; offset = 5; len = 6; }; };
assert chkExprJson { payload = { base = flake.payloadBases.nh; offset = 5; len = 6; }; };
assert chkExpr { payload = { base = "ll"; offset = 5; len = 6; }; };
assert chkExpr { payload = { protocol = "tcp"; field = "sport"; }; };
assert chkExprJson { payload = { protocol = flake.payloadProtocols.udp; field = flake.payloadFields.length; }; };
assert fails (chkExprJson { payload = { protocol = "tcp"; field = "basketball"; }; });
assert fails (chkExprJson { payload = { protocol = flake.payloadProtocols.udp; field = flake.payloadFields.vtag; }; });
# exthdr expr
assert chkExprJson { exthdr = { name = "hbh"; }; };
assert chkExprJson { exthdr = { name = flake.exthdrs.rt0; offset = 5; }; };
assert chkExprJson { exthdr = { name = flake.exthdrs.srh; field = flake.exthdrFields.tag; }; };
assert fails (chkExprJson { exthdr = { name = flake.exthdrs.hbh; offset = 5; }; });
assert fails (chkExprJson { exthdr = { name = flake.exthdrs.hbh; field = flake.exthdrFields.tag; }; });
# tcp option expr
assert chkExpr { "tcp option" = { name = "eol"; }; };
assert chkExprJson { "tcp option" = { name = flake.tcpOptions.maxseg; field = flake.tcpOptionFields.size; }; };
assert fails (chkExprJson { "tcp option" = { name = flake.tcpOptions.maxseg; field = flake.tcpOptionFields.count; }; });
# sctp chunk expr
assert chkExpr { "sctp chunk" = { name = "data"; }; };
assert chkExprJson { "sctp chunk" = { name = flake.sctpChunks.sack; field = flake.sctpChunkFields.cum-tsn-ack; }; };
assert fails (chkExpr { "sctp chunk" = { name = "not data"; }; });
assert fails (chkExprJson { "sctp chunk" = { name = flake.sctpChunks.data; field = flake.sctpChunkFields.cum-tsn-ack; }; });
# meta expr
assert chkExpr { meta.key = "length"; };
assert chkExprJson { meta.key = flake.metaKeys.secpath; };
assert fails (chkExpr { meta.key = "lengthh"; });
# rt expr
assert chkExpr { rt = { key = "classid"; family = "ip"; }; };
assert chkExprJson { rt = { key = flake.rtKeys.mtu; family = flake.families.ip6; }; };
assert chkExprJson { rt = { key = flake.rtKeys.nexthop; }; };
assert fails (chkExprJson { rt = { key = flake.rtKeys.nexthop; family = flake.families.inet; }; });
assert fails (chkExpr { rt = { key = "a"; }; });
assert fails (chkExpr { rt = { }; });
# ct expr
assert chkExpr { ct = { key = "state"; }; };
assert chkExprJson { ct = { key = flake.ctKeys.mark; }; };
assert chkExprJson { ct = { key = flake.ctKeys."ip6 saddr"; dir = flake.ctDirs.reply; }; };
assert chkExprJson { ct = { key = flake.ctKeys.proto-src; dir = flake.ctDirs.reply; }; };
assert chkExprJson { ct = { key = flake.ctKeys.l3proto; }; };
assert chkExprJson { ct = { key = flake.ctKeys.l3proto; dir = flake.ctDirs.original; }; };
assert fails (chkExprJson { ct = { key = flake.ctKeys.mark; dir = flake.ctDirs.original; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.saddr; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.proto-src; }; });
# numgen expr
assert chkExpr { numgen = { mode = "random"; mod = 5; }; };
assert chkExprJson { numgen = { mode = flake.ngModes.inc; mod = 5; offset = 5; }; };
assert fails (chkExpr { numgen = { mode = "randomm"; mod = 5; }; });
# hash expr
assert chkExpr { symhash = { mod = 5; }; };
assert chkExpr { symhash = { mod = 5; offset = 6; }; };
assert fails (chkExpr { symhash = { }; });
assert chkExpr { jhash = { mod = 5; expr.symhash.mod = 5; seed = 6; offset = 10; }; };
assert chkExpr { jhash = { mod = 5; expr.symhash.mod = 5; seed = 6; }; };
assert chkExpr { jhash = { mod = 5; expr.symhash.mod = 5; offset = 10; }; };
assert chkExpr { jhash = { mod = 5; expr.symhash.mod = 5; }; };
assert fails (chkExpr { jhash = { mod = 5; expr.aounfeuio = 5; seed = 6; offset = 10; }; });
# fib expr
assert chkExpr { fib = { result = "oif"; flags = [ "saddr" "iif" ]; }; };
assert chkExprJson { fib = { result = flake.fibResults.type; flags = with flake.fibFlags; [ saddr mark iif ]; }; };
assert fails (chkExpr { fib = { result = "oif"; flags = [ ]; }; });
assert fails (chkExpr { fib = { result = "oif"; flags = [ "iif" ]; }; });
assert fails (chkExpr { fib = { result = "oif"; flags = [ "saddrr" ]; }; });
assert fails (chkExprJson { fib = { result = flake.fibResults.type; flags = with flake.fibFlags; [ saddr daddr mark iif ]; }; });
assert fails (chkExprJson { fib = { result = flake.fibResults.type; flags = with flake.fibFlags; [ saddr mark iif oif ]; }; });
# |/^/&/<</>> exprs
assert chkExpr { "|" = [ 5 5 ]; };
assert chkExprEq { "|" = [ 5 5 ]; } { "|" = { left = 5; right = 5; }; };
assert chkExpr { "^" = [ { "&" = [ 1 2 ]; } { "<<" = [ { ">>" = [ 5 6 ]; } 7 ]; } ]; };
# verdicts (accept/drop/continue/return/jump/goto exprs)
assert chkExpr { accept = null; };
assert chkExpr { drop = null; };
assert chkExpr { continue = null; };
assert chkExpr { return = null; };
assert chkExpr { goto.target = "target"; };
assert chkExpr { jump.target = "target"; };
assert chkExpr { goto.target = "target"; };
# elem expr
assert chkExpr { elem = { val."|" = [ 1 2 ]; }; };
assert chkExpr { elem = { val = 5; timeout = 6; expires = 7; comment = "abcd"; }; };
assert fails (chkExpr { elem = { val."%" = [ 1 2 ]; }; });
# socket expr
assert chkExpr { socket.key = "transparent"; };
assert chkExprJson { socket.key = flake.socketKeys.transparent; };
assert fails (chkExpr { socket.key = "not transparent"; });
# osf expr
assert chkExpr { osf = { key = "name"; }; };
assert chkExprJson { osf = { key = flake.osfKeys.name; ttl = "loose"; }; };
assert chkExprJson { osf = { key = flake.osfKeys.name; ttl = flake.osfTtls.skip; }; };
assert fails (chkExpr { osf = { key = "namee"; }; });
assert fails (chkExprJson { osf = { key = flake.osfKeys.name; ttl = "abcd"; }; });
### STATEMENTS
# counter statement
# mangle statement
# quota statement
# limit statement
# fwd statement
# dup statement
# nat statements (snat/dnat/masquerade/redirect)
# reject statement
# set statement
# ct helper statement
# meter statement
# queue statement
# vmap statement
# ct count statement
# ct timeout statement
# ct expectation statement
# xt statement
### COMMANDS
## ADD/CREATE
# ADD TABLE 
assert chkAddDelete { table = { family = flake.families.bridge; name = "a"; }; };
# ADD CHAIN 
# base chain: with type, hook and priority
assert fieldsRequired [ "type" "hook" "prio" "policy" "dev" ] chkAddNoDelete { chain = {
  family = flake.families.netdev;
  table = "myTable";
  name = "myChain";
  type = flake.chainTypes.filter;
  hook = flake.hooks.ingress;
  prio = 0;
  dev = "eth0";
  policy = flake.chainPolicies.accept;
}; };
assert chkAddDelete { chain = {
  family = flake.families.inet;
  table = "myTable";
  name = "myChain";
}; };
assert chkTypeEq' true types.command {
  add.chain = {
    family = flake.families.inet;
    table = "myTable";
    name = "myChain";
    type = flake.chainTypes.filter;
    hook = flake.hooks.postrouting;
    prio = 100;
    policy = flake.chainPolicies.accept;
  };
} {
  add.chain = {
    family = flake.families.inet;
    table = "myTable";
    name = "myChain";
    type = flake.chainTypes.filter;
    hook = flake.hooks.postrouting;
    prio = flake.chainPriorities.srcnat;
    policy = flake.chainPolicies.accept;
  };
};
# bridge-only prio
assert fails (chkAdd {
  chain = {
    family = flake.families.inet;
    table = "myTable";
    name = "myChain";
    type = flake.chainTypes.filter;
    hook = flake.hooks.ingress;
    prio = flake.chainPriorities.out;
    policy = flake.chainPolicies.accept;
  };
});
# ADD RULE 
assert chkAdd { rule = {
  family = flake.families.inet;
  table = "myTable";
  chain = "myChain";
  expr = [ { accept = null; } ];
  comment = "a";
}; };
# ADD SET/MAP
assert chkAdd { set = {
  family = flake.families.inet;
  table = "myTable";
  name = "mySet";
  type = flake.nftTypes.ipv4_addr;
  policy = flake.setPolicies.performance;
  flags = with flake.setFlags; [ constant interval timeout ];
  elem = [ 1 2 3 4 5 6 ];
  timeout = 10;
  gc-interval = 10;
  size = 10;
}; };
# ADD MAP 
assert chkAdd { map = {
  family = flake.families.inet;
  table = "myTable";
  name = "mySet";
  type = flake.nftTypes.ipv4_addr;
  map = flake.nftTypes.ipv4_addr;
  policy = flake.setPolicies.performance;
  flags = with flake.setFlags; [ constant interval timeout ];
  elem = [ [ 1 2 ] [ 3 4 ] [ 5 6 ] ];
  timeout = 10;
  gc-interval = 10;
  size = 10;
}; };
# ADD ELEMENT 
assert chkAdd { element = {
  family = flake.families.inet;
  table = "myTable";
  name = "mySet";
  elem = [ 1 2 3 4 5 6 ];
}; };
# ADD FLOWTABLE 
assert chkAdd { flowtable = {
  family = flake.families.inet;
  table = "myTable";
  name = "myFT";
  hook = flake.hooks.postrouting;
  prio = 0;
  dev = [ "eth0" ];
}; };
# ADD COUNTER 
# ADD QUOTA 
# ADD CT_HELPER 
# ADD LIMIT 
# ADD CT_TIMEOUT 
# ADD CT_EXPECTATION
# REPLACE RULE
# INSERT RULE


### test config (manually converted from my old router)
assert (flake.exprEnumsMerged dsl.payload.tcp.flags)?syn;
assert chkTypeJson types.ruleset (with flake.dsl.payload; with flake.dsl; ruleset {
  filter = add table.netdev {
    ingress_common = insert chain [
      [(is.eq (bit.and tcp.flags (f: bit.or f.fin f.syn)) (f: bit.or f.fin f.syn)) drop]
      [(is.eq (bit.and tcp.flags (f: bit.or f.syn f.rst)) (f: bit.or f.syn f.rst)) drop]
      [(is.eq (bit.and tcp.flags (f: with f; bit.or fin syn rst psh ack urg)) 0) drop]
      [(is tcp.flags (f: f.syn)) (is.eq tcpOpt.maxseg.size (range 0 500)) drop]
      [(is.eq ip.saddr "127.0.0.1") drop]
      [(is.eq ip6.saddr "::1") drop]
      [(is.eq (fib (f: with f; [ saddr iif ]) (f: f.oif)) missing) drop]
      [return]
    ];

    ingress_lan = add chain { type = f: f.filter; hook = f: f.ingress; dev = "lan0"; prio = -500; policy = f: f.accept; }
      [(jump "ingress_common")];

    ingress_wan = add chain { type = f: f.filter; hook = f: f.ingress; dev = "wan0"; prio = -500; policy = f: f.drop; }
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
      [(mangle meta.mark ct.mark)]
      [(is.ne meta.mark 0) accept]
      [(is.eq meta.iifname "lan0") (mangle meta.mark 2)]
      [(is.eq ip.daddr "@force_unvpn4") (mangle meta.mark 1)]
      [(is.eq ip6.daddr "@force_unvpn6") (mangle meta.mark 1)]
      [(is.eq ip.daddr "@block4") drop]
      [(is.eq ip6.daddr "@block6") drop]
      [(mangle ct.mark meta.mark)];
  };
});
{
  name = "flake-checks";
  type = "derivation";
}
