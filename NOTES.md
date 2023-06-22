(based on 1.0.7)

Nftables' documentation wildly differs from the actual code! This is a
dissection of the code in `parser_json.c`. Note that I also had to
manually check each type definition/"template" to make sure that the
options/fields/keywords I support actually match what's written in
nftables code.

Q: what the hell is a counter reference/quota reference/synproxy
reference/ct timeout reference/ct expectation reference? I just use
strings for now, but actually those are stmt context expressions,
so I have no idea what they are

A: there's syntax like `ct helper set "ftp-standard"`, everything after
`set` is the reference. Since it can be a map (`ct helper set udp dport
map { 69 : "tftp-69", 5060 : "sip-5060" }`), better have it be a proper
expr

Q: what the hell are list expressions? (not set expressions)
A: I don't know exactly, initial release memo says "This is currently
  only used for specifying multiple flag values", but this isn't initial
  release, and there's proper list support in the nftables-json parser
  itself. Basically, it's mostly useless, but there may be some super
  niche use cases.

- `parse_family` - parse any family
- `json_parse_family` - parse `family` from a JSON object and ensure
  it's an IP family (`NFPROTO_IPV4`/`NFPROTO_IPV6`), or return
  `NFPROTO_UNSPEC`
- `is_keyword` - ensure something is:
  - "ether"
  - "ip"
  - "ip6"
  - "vlan"
  - "arp"
  - "dnat"
  - "snat"
  - "ecn"
  - "reset"
  - "original"
  - "reply"
  - "label"
- `is_constant` - ensure something is one of the following. The last one
  is "ICMP redirect", the other ones are protocols:
  - "tcp"
  - "udp"
  - "udplite"
  - "esp"
  - "ah"
  - "icmp"
  - "icmpv6"
  - "comp"
  - "dccp"
  - "sctp"
  - "redirect"
- `json_parse_constant` - for a constant, return `constant_expr_alloc`
  with arguments:
  - `int_loc`
  - `&icmp_type_type` for redirect, otherwise `&inet_protocol_type`
  - `BYTEORDER_HOST_ENDIAN`
  - `BITS_PER_BYTE`
  - the constant itself (e.g. `IPPROTO_TCP`, `IPPROTO_UDP`,
    `ICMP_REDIRECT`)
- `json_parse_immediate`:
  - for boolean, return a constant corresponding to said boolean
  - for integer, convert the integer to string and return a "value"
    symbol
  - for `"*"`, return wildcard expression
    - not sure what this is for, probably as a set/map key
  - for constants, return `json_parse_constant`
  - for keywords, do the next step but explicitly (there's a special
    check that does the same thing as the next step anyway)
  - for strings, return a symbol with their contents. If the string
    starts with `@`, strip the `@` and use type `SYMBOL_SET`, otherwise
    use type `SYMBOL_VALUE`.
- `json_parse_meta_expr`: look at `key` property of the object and parse
  it the same way as the DSL parser does it. Note that in the DSL,
  `meta` may be omitted for some meta keys which can obscure the
  meaning. See `default.nix`'s `metaKeys` enum comments for more info.
- `json_parse_osf_expr`:
  - ensure `key` property is `name` or `version`
  - ensure `ttl` either doesn't exist, or is `loose` or `skip` string
- `json_parse_socket_expr`:
  ensure `key` property is `transparent`, `mark` or `wildcard`
- `json_parse_payload_field`: make sure it's a valid payload field for a
  protocol. Note that the docs are sometimes wrong, better check the
  code! Also, there's no syntax for JSON to access inner
  gre/geneve/gretap/vxlan fields, and when it gets dumped it's actually
  wrong
- `json_parse_tcp_option_type`: parse tcp option (sack0-3 are special
  cased)
- `json_parse_tcp_option_field`: given a type, parse tcp option field
- `proto_lookup_byname`: lookup a protocol out of
  - `proto_eth`
  - `proto_vlan`
  - `proto_arp`
  - `proto_ip`
  - `proto_icmp`
  - `proto_igmp`
  - `proto_ip6`
  - `proto_icmp6`
  - `proto_ah`
  - `proto_esp`
  - `proto_comp`
  - `proto_udp`
  - `proto_udplite`
  - `proto_tcp`
  - `proto_dccp`
  - `proto_sctp`
  - `proto_th`
  - notably, gre, geneve, gretap, vxlan are missing, probably because of
    not being properly supported in json
- `json_parse_payload_expr`
  - if `base`, `offset` and `len` (string, int, int) are specified,
    create raw payload expr (big endian)
  - otherwise, get `protocol` and `field`, lookup `proto_lookup_byname`,
    and lookup its field via `json_parse_payload_field`. If the protocol
    is `th` (only `sport` and `dport` are supported), update some stuff
    to make it work.
- `json_parse_tcp_option_expr`
  - if `base`, `offset` and `len` (string, int, int) are specified,
    create raw tcp option expr. If `offset` is 0, flag
    `NFT_EXTHDR_F_PRESENT`. Note that this is undocumented.
  - if `name` and `field` are present, flag `NFT_EXTHDR_F_PRESENT` and
    return tcp option field expr
  - if `name` is present, return tcp option expr
- `json_parse_ip_option_type`: parse IP option (`name` from
  `ipopt_protocols`)
- `json_parse_ip_option_field`: parse IP option field
- `json_parse_ip_option_expr` - UNDOCUMENTED
  - ensure `name` is a valid option type
  - if `field` is present, return ip option field expression
  - otherwise return ip option expression
- `json_parse_sctp_chunk_field` - parse SCTP chunk field from
  `exthdr_desc`
- `json_parse_sctp_chunk_expr` - same as before, name and field
- `exthdr_lookup_byname`: lookup exthdr out of
  - `exthdr_hbh`
  - `exthdr_rt`
  - `exthdr_rt0`
  - `exthdr_rt2`
  - `exthdr_rt4` - the name is "srh"
  - `exthdr_frag`
  - `exthdr_dst`
  - `exthdr_mh`
- `json_parse_exthdr_field`: lookup exthdr field
- `json_parse_exthdr_expr` - same as above, name and field, but require
  offset for `rt0`
- `json_parse_rt_expr`:
  - key is one of
    - classid
    - nexthop
    - mtu
    - ipsec
  - family is an ip family
- `ct_key_is_dir`:
  - check that key is one of
    - `NFT_CT_L3PROTOCOL` - 7
    - `NFT_CT_SRC` - 8
    - `NFT_CT_DST` - 9
    - `NFT_CT_PROTOCOL` - 10
    - `NFT_CT_PROTO_SRC` - 11
    - `NFT_CT_PROTO_DST` - 12
    - `NFT_CT_PKTS` - 14
    - `NFT_CT_BYTES` - 15
    - `NFT_CT_AVGPKT` - 16
    - `NFT_CT_ZONE` - 17
    - `NFT_CT_SRC_IP` - 19
    - `NFT_CT_DST_IP` - 20
    - `NFT_CT_SRC_IP6` - 21
    - `NFT_CT_DST_IP6` - 22
- `json_parse_ct_expr`:
  - ensure `key` is a valid ct key
  - if `dir` is present
    - ensure it's `original` or `reply`
    - ensure that `ct_key_is_dir`
  - VERY NOTABLY, the docs state that you can use `family` property to
    specify the IP family for `saddr`/`daddr`. Instead, you have to use
    `ip saddr`/`ip6 saddr` as the key!
- `json_parse_numgen_expr`:
  - ensure `mode` is a string and `mod` is a number
  - get `offset` as int, ignoring any errors (so it stays 0 if it wasnt
    set/wasnt an int)
  - ensure mode is inc/random
- `json_parse_hash_expr`:
  - ensure `mod` is an int, get `offset` same as above - that's it for
    symhash
  - for jhash, also parse mandatory `expr` and optional `seed`
    - parse expr with parent context flags
- `fib_flag_parse`: `1 << index in [saddr, daddr, mark, iif, oif]` or
  error
- `json_parse_fib_expr`:
  - ensure result is in `oif` `oifname` `type`
  - if `flags` is set, get it as a single flag or as an array of flags
  - ensure exactly one of saddr, daddr flags is set
  - ensure at most one of iif, oif is set
- `json_parse_binop_expr`:
  - ensure op is `|/^/&/>>/<<`
  - ensure lhs is a valid expr in primary context
  - ensure rhs is a valid expr in rhs context
- `json_parse_concat_expr`:
  - make sure it's an array
  - make sure inner exprs make sense in concat context
- `json_parse_prefix_expr`:
  - get `addr` as primary expr
  - get `len` as int
- `json_parse_range_expr`:
  - ensure both elements of the list are valid prim exprs
- `json_parse_verdict_expr`:
  - ensure it's one of continue, jump, goto, return, accept, drop
  - if goto/jump, ensure target (string) is present
- `json_parse_set_expr`:
  - if it isn't an array, parse it as an immediate value
    (int/string/etc). If it's `@something` string, return that (set
    reference). otherwise create a set with that immediate value as the
    sole element.
  - otherwise, for each element:
    - for two-element array elements:
      - left value is an expr with rhs context, it might be a formal
        `elem` object
      - right value is an expr with set rhs context, it's what the first
        value maps to
    - for non-array elements, same as left value above applies
- `json_parse_map_expr`:
  - ensure key is valid map lhs expr
  - ensure data is valid rhs expr
    - usually this is a set expression
- `json_parse_set_elem_expr`:
  - ensure `val` is a valid expr (same context)
  - get optional timeout (seconds), expires (seconds), comment (str)
- `json_parse_xfrm_expr`: UNDOCUMENTED
  - get `key` string
  - (xfrm.c) get template for key from `xfrm_templates`
    - daddr (ipv4)
    - saddr (ipv4)
    - daddr (ipv6)
    - saddr (ipv6)
    - reqid
    - spi
  - get optional ip `family` (`json_parse_family`), adjust daddr/saddr
    accordingly
  - get optional `dir` (string: in/out)
  - get optional `spnum` (0..=255)
- `json_parse_expr` - parse expression with context
- `json_parse_dtype_expr` - parse datatype
  - for strings, check that its one of
    - `invalid`
    - `verdict`
    - `nf_proto`
    - `bitmask`
    - `integer`
    - `string`
    - `ll_addr`
    - `ipv4_addr`
    - `ipv6_addr`
    - `ether_addr`
    - `ether_type`
    - `arp_op`
    - `inet_proto`
    - `inet_service`
    - `icmp_type`
    - `tcp_flag`
    - `dccp_pkttype`
    - `mh_type`
    - `time`
    - `mark`
    - `iface_index`
    - `iface_type`
    - `realm`
    - `classid`
    - `uid`
    - `gid`
    - `ct_state`
    - `ct_dir`
    - `ct_status`
    - `icmpv6_type`
    - `pkt_type`
    - `icmp_code`
    - `icmpv6_code`
    - `icmpx_code`
    - `devgroup`
    - `dscp`
    - `ecn`
    - `fib_addtype`
    - `boolean`
    - `ifname`
    - `igmp_type`
    - `time`
    - `hour`
    - `day`
    - `cgroupsv2`
  - for arrays, same for all elements (compound type)
- `json_parse_match_stmt`:
  - `op` is the operator. All operators get checked, including unary
    `!`, `hton`, `ntoh`. Semantics are unknown, so whatever.
  - `in` is hardcoded to `OP_IMPLICIT`, which means "do whatever
    nftables would do if there wasn't an operator between those two
    values"
  - `left` is a valid expr (same context)
  - `right` is a valid expr (rhs context)
- `json_parse_counter_stmt`:
  - `null` means anonymous counter
  - `packets` and `bytes` as int properties is an anonymous counter as
    well
  - anything else means "counter reference". Yes *anything* - it's an
    expression, specifically in statement context.
- `json_parse_verdict_stmt` - calls "parse verdict expr"
- `json_parse_mangle_stmt`:
  - get `key` and `value` exprs
  - make sure `key` is a valid expr (mangle context)
  - make sure `value` is a valid expr (stmt context)
  - make sure key is exthdr/payload/meta/ct/ct helper expr
- this is when I noticed - there's no code for parsing ct
  helper/timeout/expectation expressions despite it being documented!
  Whatever, no big deal...
- `rate_to_bytes`:
  - kbytes: multiply by 1024
  - mbytes: multiply by `1024*1024`
- `json_parse_quota_stmt`:
  - if val (num) is present:
    - also (all optional) parse inv (bool), `val_unit` (str), used
      (num), `used_unit` (str)
    - `rate_to_bytes` on `val`/`val_unit`, `used`/`used_unit`
  - otherwise: quota reference
- `seconds_from_unit`:
  - week: `60*60*24*7`
  - day: `60*60*24`
  - hour: `60*60`
  - minute: `60`
- `json_parse_limit_stmt`:
  - if rate (num) and per (string) are present:
    - also (all optional) parse `rate_unit` (string), inv (bool), burst
      (num), `used_unit` (str)
    - `seconds_from_unit` as applicable, but if `rate_unit` is packets
      (default) then those get ignored and burst defaults to 5
      (if it isn't `packets` then burst defaults to 0)
  - otherwise parse limit reference
- `json_parse_fwd_stmt`:
  - get `dev` expr in stmt context
  - get optional ip `family` (`json_parse_family`)
  - if family is set, get optional `addr` expr in stmt context,
    otherwise ignore family
- `json_parse_flow_offload_stmt`:
  - get `op` and `flowtable` strings
  - ensure `flowtable` starts with `@` and strip that
  - ensure `op` is `add`
- `json_parse_notrack_stmt`: do nothing
- `json_parse_dup_stmt`:
  - parse `addr` expr (stmt ctx)
  - optionally parse `dev` expr (stmt ctx)
- `json_parse_secmark_stmt`: parse object as expr in stmt ctx
- `json_parse_nat_flag`: parse string
  random/fully-random/persistent/netmap
- `json_parse_nat_flags`: parse one flag to array or an array of
  flags
- `json_parse_nat_type_flag`: parse string interval/prefix/concat
  ^ UNDOCUMENTED
- `json_parse_nat_type_flags`: see above but many (or 1 to many)
- `nat_type_parse`: snat/dnat/masquerade/redirect
- `json_parse_nat_stmt` (activated for the above types)
  - `json_parse_family` (`family`, optional)
  - parse opt `addr` as stmt expr
  - parse opt `port` as stmt expr
  - parse opt `flags` via `json_parse_nat_flags`
  - parse opt `type_flags` via `json_parse_nat_type_flags`
- `json_parse_tproxy_stmt`:
  - parse opt family (`json_parse_family`)
  - parse opt `addr` as expr in stmt context
  - parse opt `port` as expr in stmt context
- `json_parse_reject_stmt`:
  - parse opt `type` as string (tcp reset, icmp, icmpx, icmpv6)
  - parse `expr` as immediate expr
- `json_parse_set_stmt_list`: ensure it's an array and parse each stmt
- `json_parse_set_stmt`:
  - get op (str), elem (obj), set (str)
  - ensure op is add/update/(undocumented) delete
  - ensure set starts with @
  - parse elem as expr in ses context
  - optionally parsse `stmt` via the above fn
- `json_parse_log_flag`: parse string
  tcp sequence/tcp options/ip options/skuid/ether/all
- `json_parse_log_flags` - you get the idea
- `json_parse_log_stmt`: all optional:
  - `prefix` str
  - `group` int
  - `snaplen` int
  - `queue-threshold` int
  - `level` str (full list of valid vals in `syslog_level` in
    `src/statement.c`)
  - `flags` see above fn
- `json_parse_synproxy_flag`: parse string timestamp/sack-perm
- `json_parse_synproxy_flags`
- `json_parse_synproxy_stmt`:
  - if null, no options
  - otherwise all optional:
    - mss - non-negative int
    - wscale - non-negative int
    - flags - see above fn
  - however if no options in the above list are set:
    - expr (synproxy reference) in stmt context
- `json_parse_cthelper_stmt`: ct helper reference 
- `json_parse_cttimeout_stmt`: ct timeout reference
- `json_parse_ctexpect_stmt` - ct expectation reference
- `json_parse_meter_stmt`:
  - parse name (string), key (expr in ses context), stmt (stmt)
  - parse opt size (int)
- `queue_flag_parse`: bypass/fanout
- `json_parse_queue_stmt`:
  - opt num (expr in stmt context)
  - opt `flags` (see above)
- `json_parse_connlimit_stmt`: (`ct count`) val (int), inv (opt bool)
- `json_parse_optstrip_stmt` - `reset` stmt (just takes an expr)
- `json_parse_cmd_add`: used for create/add/destroy
- `json_parse_cmd_replace`: used for replace/insert
- `json_parse_cmd_list`: used for list, uses `add_*` parsers
- `json_parse_cmd_reset`: used for reset, special code for `rule`,
  otherwise uses `add_*` parsers
- `json_parse_cmd_flush`: used for flush, uses `add_*` parsers
- `json_parse_cmd_rename`: used for rename, special code
- overall, command docs are surprisingly complete (though it's good to
  mention that `family` and `table` is required practically everywhere
  even if you're removing or listing, not adding an object). Also, `ct
  helper`s don't receive a handle and `ct timeout`s receive `policy`
  instead of `state` and `value`, `ct X` objects only allow `tcp` and
  `udp` protocols even though the docs mention way more and Santa isn't
  real.
- metainfo: only checks `json_schema_version` (1 at the moment).
  Serializes also `version` and `release_name`
