# compiles json into the nftables dsl
{ lib
, notnft
, ... }:

let
  optPreSuf = pre: suf: x: if x != null && x != "" then "${pre}${toString x}${suf}" else "";
  optPre = pre: optPreSuf pre "";
  optCatPreSuf = pre: suf: inf: x:
    let y = builtins.filter (x: x != null && x != "") x; in
    if y != null then "${pre}${cat inf (map toString y)}${suf}" else "";
  optCat = optCatPreSuf "" "";
  cat = builtins.concatStringsSep;
  mapStr = f: s: if s != null && s != "" then f s else s;
  compileStr = s: let s' = toString s; in if builtins.match "^[a-zA-Z][a-zA-Z0-9/\\-_.]*$" s' then s' else builtins.toJSON s;
  mapComps = mapStr compileStr;
in rec {
  inherit compileStr;
  compileSetElem = x:
    if builtins.isList x && builtins.length x == 2 then cat " : " (map compileExpr x)
    else compileExpr x;
  compileExpr = x:
    if builtins.isString x && lib.hasPrefix "@" x then "@${compileStr (lib.removePrefix "@" x)}"
    else if x == "*" then x
    else if builtins.isString x then compileStr x
    else if builtins.isPath x then compileStr (toString x)
    else if builtins.isInt x then toString x
    else if builtins.isBool x then (if x then "exists" else "missing")
    else if builtins.isFloat x then throw "nftables doesn't support floating point numbers"
    else if builtins.isNull x then throw "nftables doesn't support nulls"
    else if builtins.isFunction x then throw "nftables doesn't support functions"
    else if builtins.isList x then cat ", " (map compileExpr x)
    else if x?concat then cat " . " (map compileExpr x.concat)
    else if x?jump then "jump ${compileExpr x.jump}"
    else if x?goto then "goto ${compileExpr x.goto}"
    else if x?set && !(builtins.isList x.set) then compileExpr x.set
    else if x?set then "{ ${cat ", " (map compileSetElem x.set)} }"
    else if x?map then "${compileExpr x.map.key} map ${compileExpr x.map.data}"
    else if x?prefix then "${compileExpr x.prefix.addr}/${toString x.prefix.len}"
    else if x?range then cat "-" (map compileExpr x.range)
    else if x?payload.base then "@${x.payload.base},${toString x.payload.offset},${toString x.payload.len}"
    else if x?payload then "${x.payload.protocol} ${x.payload.field}"
    else if x?exthdr.offset && x.exthdr.field == "reserved" && x.exthdr.offset <= 0 then "${x.exthdr.name} ${x.exthdr.field}"
    else if x?exthdr.offset && x.exthdr.field == "reserved" then "${x.exthdr.name} addr[${toString (x.exthdr.offset + 1)}]"
    else if x?exthdr.offset && x.exthdr.field == "addr[1]" then "${x.exthdr.name} addr[${toString x.exthdr.offset}]"
    else if x?exthdr.offset && x.exthdr.field == "addr[2]" then "${x.exthdr.name} addr[${toString (x.exthdr.offset - 1)}]"
    else if x?exthdr.field then "${x.exthdr.name} ${x.exthdr.field}"
    else if x?exthdr then "exthdr ${x.exthdr.name}"
    else if x?"tcp option".base then "tcp option @${toString x."tcp option".base},${toString x."tcp option".offset},${toString x."tcp option".len}"
    else if x?"tcp option".field then "tcp option ${x."tcp option".name} ${x."tcp option".field}"
    else if x?"tcp option" then "tcp option ${x."tcp option".name}"
    else if x?"ip option".field then "ip option ${x."ip option".name} ${x."ip option".field}"
    else if x?"ip option" then "ip option ${x."ip option".name}"
    else if x?"sctp chunk".field then "sctp chunk ${x."sctp chunk".name} ${x."sctp chunk".field}"
    else if x?"sctp chunk" then "sctp chunk ${x."sctp chunk".name}"
    else if x?meta && ((notnft.metaKeys.${x.meta.key}.__info__ or {}).unqualified or false) then x.meta.key
    else if x?meta then "meta ${x.meta.key}"
    else if x?rt then optCat [ "rt" (x.rt.family or null) x.rt.key ]
    else if x?ct then optCat [ "ct" (x.ct.dir or null) (x.ct.family or null) x.ct.key ]
    else if x?ipsec then optCat " " [ "ipsec" x.ipsec.dir (optPre "spnum " (x.ipsec.spnum or null)) (x.ipsec.family or null) x.ipsec.key ]
    else if x?numgen then "numgen ${x.numgen.mode} mod ${toString x.numgen.mod}${optPre " offset " (x.numgen.offset or null)}"
    else if x?jhash then "jhash ${compileExpr x.jhash.expr} mod ${toString x.jhash.mod}${optPre " seed " (x.jhash.seed or null)}${optPre " offset " (x.jhash.offset or null)}"
    else if x?symhash then "symhash ${x.symhash.mode} mod ${toString x.symhash.mod}${optPre " offset " (x.symhash.offset or null)}"
    else if x?fib then let flags = if builtins.isList x.fib.flags then cat " . " x.fib.flags else x.fib.flags; in "fib ${flags} ${x.fib.result}"
    else if x?"|" || x?"&" || x?"^" || x?"<<" || x?">>" then let y = builtins.head (builtins.attrNames x); in "(${compileExpr x.${y}.left}${y}${compileExpr x.${y}.right})"
    else if x?accept || x?drop || x?continue || x?return then builtins.head (builtins.attrNames x)
    else if x?goto then "goto ${x.goto.target}"
    else if x?jump then "jump ${x.jump.target}"
    else if x?elem then optCat " " [ (compileExpr x.elem.val) (optPre "timeout " (x.elem.timeout or null)) (optPre "expires " (x.elem.expires or null)) (optPre "comment " (mapStr compileExpr (x.elem.comment or null))) ]
    else if x?socket then "socket ${x.socket.key}"
    else if x?osf then "osf${optPre " ttl " x.osf.ttl} ${x.osf.key}"
    else throw "unexpected expr ${builtins.toJSON x}";
  compileStmt = x:
    throw "todo";
  compileObject = obj:
    if obj?table then let x = obj.table; in optCat " " [
      "table"
      (mapComps (x.family or null))
      (mapComps (x.name or null))
      (optPre "handle " (x.handle or null))
    ]
    else if obj?chain then let x = obj.chain; in optCat " " [
      "chain"
      (mapComps (x.family or null))
      (mapComps (x.table or null))
      (mapComps (x.name or null))
      (optPre "handle " (x.handle or null))
      (optCatPreSuf "{ " " }" " " [
        (optPre "type " (x.type or null))
        (optPre "hook " (x.hook or null))
        (optPre "device " (x.dev or null))
        (optPre "priority " (x.prio or null))
        (optPre "policy " (x.policy or null))
      ])
    ]
    else if obj?rule then let x = obj.rule; in optCat " " [
      "rule"
      (mapComps (x.family or null))
      (mapComps (x.table or null))
      (mapComps (x.chain or null))
      (optPre "handle " (x.handle or null))
      (optPre "index " (x.index or null))
      (optCat " " (map compileStmt (lib.toList (x.expr or []))))
      (mapComps (x.comment or null))
    ]
    else if obj?set then let x = obj.set; in throw "todo"
    else if obj?map then let x = obj.map; in throw "todo"
    else if obj?element then let x = obj.element; in throw "todo"
    else if obj?flowtable then let x = obj.flowtable; in throw "todo"
    else if obj?counter then let x = obj.counter; in throw "todo"
    else if obj?quota then let x = obj.quota; in throw "todo"
    else if obj?"ct helper" then let x = obj."ct helper"; in throw "todo"
    else if obj?limit then let x = obj.limit; in throw "todo"
    else if obj?"ct timeout" then let x = obj."ct timeout"; in throw "todo"
    else if obj?"ct expectation" then let x = obj."ct expectation"; in throw "todo"
    else throw "couldn't compile object with keys ${builtins.toJSON (builtins.attrNames obj)}";
      
  compileCommand = cmd:
    if cmd?metainfo then "# ${builtins.toJSON cmd}"
    else let attr = lib.head (builtins.attrNames cmd); in "${attr} ${compileObject cmd.${attr}}";

  compileRuleset = { nftables }:
    cat "\n" (map compileCommand nftables);
}
