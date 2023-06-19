# Library reference

There are too many enums to list them here, see source code for
reference.

- `dsl` - the DSL (reference: see [below](#dsl-reference))
- `types` - contains the NixOS option types for the nftables schema
  - `statement` - a statement
  - `command` - a command
  - `ruleset` - a ruleset (a JSON object containing `nftables`)
  - `expression` - an expression
  - there's much much more, see code for details

Currently, you can only create JSON rules. Later you may be able to
compile it to plain nftables.

# DSL reference

You are expected to read this after reading the comments in the sample
in [README.md](./README.md). Additionally, prior experience with
nftables is strongly recommended.

## Enums

Nftables has many "constants", where you can use a string to refer to a
specific value. I call them enums. For example, you can use `"syn"` to
refer to the TCP flag `syn`.

If you don't want to use strings, you can use my premade enum objects.

For example, `notnft.tcpFlags.syn` refers to the `syn` tcp flag. But
this is quite bulky and hard to remember. Instead, anywhere you would
use an enum, you can use a function that takes that enum! For example,
instead of doing `bit.and payload.tcp.flags notnft.tcpFlags.syn`, you
can do `bit.and payload.tcp.flags (f: f.syn)`.

### One Enum to Rule Them All

Additionally, if you find this syntax bulky, I've implemented an
advanced feature called "One Enum to Rule Them All" (`oneEnum` for
short). If you do `with oneEnumToRuleThemAll;`, you can simply use
whatever constants you please, the DSL will automatically detect wrongly
used values. However, be aware that

1. Some values (like `add` or `icmp` or `redirect`) can't be added to
   One Enum, because they would clash with DSL's own values. However, I
   got it to work anyway using powers of black magic. The black magic
   is disabled by default, but enabled if you do
   `with oneEnumToRuleThemAll;`
   - Specifically, `oneEnumToRuleThemAll` contains a copy of the DSL
     with hacks enabled (if you do `with dsl;` after
     `with oneEnumToRuleThemAll;`, the hacks will be disabled, but One
     Enum will not work as well as it could).
   - I think it's fairly unlikely that those hacks will break anything,
     but use them at your own risk!
2. You will not get the exact line where you used the wrong value
   in error messages if you do this.
3. The enum may pollute the namespace, as there really are a lot of
   differently named constants in nftables.

Example:
`with dsl.oneEnum; bit.or payload.tcp.flags fin syn rst psh ack urg`

## Commands

- `create` - make sure something doesnt already exist and create it
- `add` - add something if it doesnt already exist
- `insert` - for prepending rules to an existing chain
- `delete` - delete something, error if it doesn't exist
- `destroy` - delete something if it exists
- `flush` - clear something
- `reset` - reset something's state
- ~~`rename` - not implemented in the DSL~~

## "Objects"

Here, "objects" means whatever can be created with commands (like tables
or chains).

- `table` - takes mandatory `family` and optional `comment` attrs
  - You can pass an attrset with the table's contents, each key will
    become the associated object's name.
    - Alternatively, you can pass the table contents directly or in a
      list, but then you'll have to pass `name` to each object manually.
  - All other objects either have to be part of a table, or explicitly
    passed `family` (table family) and `table` (table name)
- `chain` - takes optional `type`, `hook`, `prio`, `dev`, `policy`,
  `comment` attrs.
  - You can pass rules to the chain. Each rule is a list of statements.
    You can pass either a list of rules (`chain [[a] [b] [c]]`), or you
    can repeatedly apply rules to the chain (`chain [a] [b] [c]`).
- `set` - takes `type`, and optional `policy`, `flags`, `timeout`,
  `gc-interval`, `size` attrs.
  - You can pass a list of expressions to the set to initialize it with
    some values.
- `map` - same as above, but also takes `map` attr (in this case `type`
  is key type, and `map` is value type).
  - If you want to initialize it with certain values, you have to pass
    a list of lists of size 2 (1st value is the key, 2nd is the
    associated value).
- `flowtable`, `counter`, `quota`, `secmark`, `ctHelper`, `limit`,
  `ctTimeout`, `ctExpectation`, `synproxy` - refer to libnftables-json
  documentation for more info on those.

## Statements

Each rule contains one or more statements. Unless the rule is a
"verdict", the next rule will be executed after the previous one.

The following statements are supported:

- `accept` - stop evaluation and accept the packet
- `drop` - stop evaluation and accept the packet
- `continue` - go to the next rule
- `return` - return from the current rule and continue with the next
  rule in the previous chain
- `jump <CHAIN_NAME>` - "call" another chain (so it can be returned from
  to continue evaluating this chain)
- `goto <CHAIN_NAME>` - "call" another chain, but don't push the current
  position to the call stack (so returning from that chain will return
  into the parent chain)
- `is`, `is.eq`, `is.ne`, `is.gt`, `is.lt`, `is.ge`, `is.le` -
  comparison operators (implicit, `==`, `!=`, `>`, `<`, `>=`, `<=`).
  Each of those takes two expressions and compares them.
- `counter` - use an anonymous counter to count the number of
  packets/bytes.
  - `counter { ... }` - pass some attrs (`packets`/`bytes`) to the
    counter. Refer to libnftables-json docs for more info.
- `mangle <A> <B>` - change packet data/meta info A to B
- `quota { ... }` - pass some attrs to quota statement (refer to
  libnftables-json docs)
- `limit { ... }` - pass some attrs to limit statement (refer to
  libnftables-json docs)
- `fwd { ... }` - pass some attrs to fwd statement - forward a packet to
  a different destination (refer to libnftables-json docs)
- `notrack` - disable connection tracking for the packet.
- `dup { ... }` - pass some attrs to dup statement - duplicate a packet
  to a different destination (refer to libnftables-json docs)
- `snat <ip>` / `snat <ip> <port>` / `snat { ... }` /
  `snat <ip> { ... }` / `snat <ip> <port> { ... }` - perform source
  network address translation, optionally specifying ip/port, optionally
  specifying the rest of the attrs (refer to libnftables-json docs)
- `dnat` - same syntax as above, but destination network address
  translation
- `masquerade <port>` / `masquerade { ... }` /
  `masquerade <port> { ... }` - perform SNAT to the outgoing interface's
  IP address.
- `redirect` - same syntax, but DNAT to local host's IP address.
- `reject` / `reject { ... }` - reject (with optional attrs, see
  libnftables-json docs)
- `set.add <set> <elem>` / `set.update <set> <elem>` /
  `set.delete <set> <elem>` - add/update/delete `elem` to/from `set`
- `log { ... }` - log with attrs (see libnftables-json docs)
- `ctHelper <expr>` - set a packet's ct helper to `<expr>`
- `meter { ... }` - see libnftables-json docs
- `queue { ... }` - see libnftables-json docs
- `vmap <expr> <data>` - apply a verdict depending on `<expr>`. `<data>`
  can either be a list of lists of size 2, each being a key-value pair,
  or a map with keys being strings and values being verdicts.
- `ctCount <n>` - set conntrack connection count threshold
  - `ctCount { ... }` - see nftables-json docs for `ct count` statement.
- `ctTimeout <expr>` - set a packet's ct timeout to `<expr>`
- `ctExpectation <expr>` - set a packet's ct expectation to `<expr>`
- `flow.add <name>` - select the flowtable for flow offloading
- `tproxy { ... }` - see libnftables-json docs
- `synproxy { ... }` - see libnftables-json docs
- `reset <expr>` - reset a tcp option expression
- `secmark <expr>` - set a packet's secmark to `<expr>`

## Expressions

- `"@<set_name>"` - set reference/flowtable reference
- `"*"` - wildcard (not sure what this is used for)
- `[ a b c ]` - list expression (not sure what this is used for)
- `concat <a> <b> <c>...` / `concat [ <a> <b> <c> ... ]` - concat
  multiple values (same as `a . b . c` in nftables)
- `set [ a b c ... ]` - create an anonymous set (same as `{ a, b, c }`
  in nftables)
- `set [ [ a b ] [ c d ] ... ]` - create an anonymous map (same as
  `{ a : b, c : d }` in nftables)
- `map <expr> <mapping>` - select a value based on `expr`'s value.
  Mapping can either be a list of lists of size 2 (each being a
  key-value pair), or if the keys are strings it can be an attrset.
- `cidr <prefix> <length>` - create an IP prefix expression (e.g.
  `127.0.0.0/8` is `cidr "127.0.0.1" 8`)
- `range a b` - a range from a to b, same as nftables's `a-b`
- `payload.<protocol>.<field>` - access a protocol's field. It is
  convenient to do `with payload;` to be able to quickly access each
  field. Example: `payload.tcp.flags` accesses TCP flags of a packet.
- `exthdr.<header>` - reference an IPv6 extension header
- `exthdr.<header>.<field>` - reference an IPv6 extension header field
- `tcpOpt.<name>` - reference a TCP option
- `tcpOpt.<name>.<field>` - reference an TCP option field
- `ipOpt.<name>` - reference an IP option
- `ipOpt.<name>.<field>` - reference an IP option field
- `sctpChunk.<name>` - reference an SCTP chunk
- `sctpChunk.<name>.<field>` - reference an SCTP chunk field
- `meta.<key>` - reference a packet's metadata (e.g. `meta.iifname`)
- `rt.<family>.<key>` / `rt.<key>` - access routing data associated with
  a packet (key being `classid`, `nexthop`, `mtu`, `ipsec`)
- `ct.<key>` / `ct.<dir>.<key>` / `ct.<dir>.<family>.<key>` - conntrack
  expression (see nftables man for more info)
- `numgen.inc <mod>` / `numgen.random <mod>` / `numgen.inc { ... }` /
  `numgen.random { ... }` - generate a random number (see
  libnftables-json docs/nftables man for more info). `mod` is modulo.
- `jhash <expr> <mod>` / `jhash <expr> { ... }` - hash packet data
- `symhash <mod>` / `symhash { ... }` - hash packet
- `fib <flags> <result>` - query fib based on `flags`, fetching `result`
- `bin.and`, `bin.or`, `bin.xor`, `bin.lsh`, `bin.rsh` - binary
  operations - `&` / `|` / `^` / `<<` / `>>`. Each takes any amount of
  arguments (e.g. `bin.or a b c d` translates to `((a|b)|c)|d`).
- `accept`/`drop`/`continue`/`return`/`jump`/`goto` - same as
  statements, but used in `vmap` statement.
- `elem { ... } <expr>` / `elem <expr> { ... }` /
  `elem { val = <expr>, ... }` - enrich `<expr>` with optional
  `timeout`, `expires` and `comment` when adding to a set. For maps,
  only the key can be an `elem`.
- `socket.<key>`> - search for an associated socket and get some
  associated info. Keys are `transparent`, `mark`, `wildcard`.
- `osf.<key>` / `osf.ttl.<ttl>.<key>` / `osf.<ttl>.<key>` - do operating
  system fingerprinting. Key is `name` (OS signature name) or `version`
  (OS version), TTL is `loose` (check fingerprint's TTL) or `skip`
  (don't check it).
- `ipsec.<dir>.<key>` / `ipsec.<dir>.<family>.<key>` / 
  `ipsec.<dir>.<key> { spnum = ...; }` /
  `ipsec.<dir>.<family>.<key> { spnum = ...; }` - ipsec expression with
  optional spnum (see nftables man).
- `dccpOpt <type>` - create a reference to a DCCP option (type is
  numeric)

## Warning

The DSL does some funky stuff behind the scenes, so you can't serialize
the DSL objects via `builtins.toJSON` as-is, and if you want to create
an expression/statement/command via the DSL without enclosing it in
`dsl.ruleset`, whether it's for passing it to the NixOS module system or
calling `builtins.toJSON`, you have to make sure to get rid of that
"funkiness".

Make sure to call `dsl.compile` on any expression/statement that
isn't enclosed in a `table`, or on any command (e.g. `add table`) that
isn't enclosed in a `ruleset`.

