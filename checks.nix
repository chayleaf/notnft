{ flake, lib, ... }:

let
  inherit (flake) types;
  inherit (lib.modules) evalModules;
  # check that `expr` is of type `type`, and that the merged value equals `expected`
  # if `json` is true, compare jsons
  chkTypeEq' = json: type: expected: expr:
    let val = (evalModules {
    modules = [
      {
        options.val = lib.mkOption {
          inherit type;
          default = throw "error";
        };
        config.val = expr;
      }
    ];
  }).config.val;
  in
    # assert lib.assertMsg val.success "Invalid type for ${builtins.toJSON expr}";
    lib.assertMsg (if json then builtins.toJSON val == builtins.toJSON expected else val == expected) "Invalid value for ${builtins.toJSON expr} (got ${builtins.toJSON val}, expected ${builtins.toJSON expected})";
  chkTypeEq = chkTypeEq' false;
  # check that `x` is an expression and the merged value equals `x`
  chkExpr = x: chkTypeEq types.expression x x;
  # check that `x` is an expression and the merged value equals `x` when both are converted to json
  # how this is used: enum values in notnft have a __tostring attr, which automatically gets called
  # by toJSON. This means that despite merging to a different value (string rather than opaque enum),
  # values are still considered equal.
  chkExprJson = x: chkTypeEq' true types.expression x x;
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
  fieldsOptional = fields: func: x: assert func x; builtins.all (field: func (removeAll [ field ] x)) fields;
  chkAddDelete = x:
    assert chkAdd x;
    assert chkDelete x;
    assert chkDelete (addAll { handle = 5; } (removeAll [ "name" ] x));
    assert chkDelete (addAll { handle = 5; } (preserveAll [ "table" ] x));
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
assert fails (chkExpr { payload = { protocol = "tcp"; field = "basketball"; }; });
assert fails (chkExpr { payload = { protocol = flake.payloadProtocols.udp; field = flake.payloadFields.vtag; }; });
# exthdr expr
assert chkExpr { exthdr = { name = "hbh"; }; };
assert chkExprJson { exthdr = { name = flake.exthdrs.hbh; offset = 5; }; };
assert chkExprJson { exthdr = { name = flake.exthdrs.srh; field = flake.exthdrFields.sid; }; };
assert fails (chkExprJson { exthdr = { name = flake.exthdrs.hbh; field = flake.exthdrFields.sid; }; });
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
assert chkExprJson { ct = { key = flake.ctKeys.saddr; family = flake.families.ip6; dir = flake.ctDirs.reply; }; };
assert chkExprJson { ct = { key = flake.ctKeys.proto-src; dir = flake.ctDirs.reply; }; };
assert chkExprJson { ct = { key = flake.ctKeys.l3proto; }; };
assert chkExprJson { ct = { key = flake.ctKeys.l3proto; dir = flake.ctDirs.original; }; };
assert fails (chkExprJson { ct = { key = flake.ctKeys.mark; family = flake.families.ip; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.mark; dir = flake.ctDirs.original; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.saddr; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.saddr; family = flake.families.ip6; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.proto-src; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.proto-src; family = flake.families.ip; dir = flake.ctDirs.original; }; });
assert fails (chkExprJson { ct = { key = flake.ctKeys.l3proto; dir = flake.ctDirs.original; family = flake.families.ip; }; });
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
assert chkExpr { fib = { result = "oif"; }; };
assert chkExpr { fib = { result = "oif"; flags = [ "saddr" ]; }; };
assert chkExprJson { fib = { result = flake.fibResults.type; flags = with flake.fibFlags; [ saddr daddr mark iif oif ]; }; };
assert fails (chkExpr { fib = { result = "oif"; flags = [ "saddrr" ]; }; });
# |/^/&/<</>> exprs
assert chkExpr { "|" = [ 5 5 ]; };
assert chkExprEq { "|" = [ 5 5 ]; } { "|" = { lhs = 5; rhs = 5; }; };
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
assert chkExprJson { osf = { key = flake.osfKeys.name; ttl = flake.osfTtl.skip; }; };
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
    prio = flake.priorities.srcnat;
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
    prio = flake.priorities.out;
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
{
  name = "flake-checks";
  type = "derivation";
}
