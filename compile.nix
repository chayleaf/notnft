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
  mapStr = f: s: if s != null && s != "" && s != [] then f s else "";
  compileStr = s: let s' = toString s; in if builtins.match "^[a-zA-Z][a-zA-Z0-9/\\-_.]*$" s' then s' else builtins.toJSON s;
  mapComps = mapStr compileStr;
in rec {
  inherit compileStr;
  compileSetElem = x:
    if builtins.isList x && builtins.length x == 2 then cat " : " (map compileExpr x)
    else compileExpr x;
  compileSetElems = x:
    if builtins.isList x then cat ", " (map compileSetElem x)
    else if builtins.isAttrs x then cat ", " (lib.mapAttrsToList (k: v: compileSetElem [ k v ]) x)
    else compileSetElem x;
  compileExpr = x:
    if builtins.isString x && lib.hasPrefix "@" x then "@${compileStr (lib.removePrefix "@" x)}"
    else if x == "*" then x
    else if builtins.isString x then compileStr x
    else if x?__toString then compileStr (toString x)
    else if builtins.isPath x then compileStr (toString x)
    else if builtins.isInt x then toString x
    else if builtins.isBool x then (if x then "exists" else "missing")
    else if builtins.isFloat x then throw "nftables doesn't support floating point numbers"
    else if builtins.isNull x then throw "nftables doesn't support nulls"
    else if builtins.isFunction x then throw "nftables doesn't support functions"
    else if builtins.isList x then cat ", " (map compileExpr x)
    else if builtins.length (builtins.attrNames x) != 1 then throw "invalid attr count in expression with attrs ${cat ", " (builtins.attrNames x)}"
    else let key = builtins.head (builtins.attrNames x); val = x.${key}; in {
      concat = cat " . " (map compileExpr val);
      jump = "jump ${compileStr val.target}";
      goto = "goto ${compileStr val.target}";
      set =
        if builtins.isString val && lib.hasPrefix "@" val then val
        else if !(builtins.isList val) then "{ ${compileExpr val} }"
        else "{ ${compileSetElems val} }";
      map = "${compileExpr val.key} map { ${compileSetElems val.data} }";
      prefix = "${compileExpr val.addr}/${toString val.len}";
      range = cat "-" (map compileExpr val);
      payload =
        if val?base then "@${val.base},${toString val.offset},${toString val.len}"
        else "${val.protocol} ${val.field}";
      exthdr =
        if val?offset && val.field == "reserved" && val.offset <= 0 then "${val.name} ${val.field}"
        else if val?offset && val.field == "reserved" then "${val.name} addr[${toString (val.offset + 1)}]"
        else if val?offset && val.field == "addr[1]" then "${val.name} addr[${toString val.offset}]"
        else if val?offset && val.field == "addr[2]" then "${val.name} addr[${toString (val.offset - 1)}]"
        else if val?field then "${val.name} ${val.field}"
        else "exthdr ${val.name}";
      "tcp option" =
        if val?base then "tcp option @${toString val.base},${toString val.offset},${toString val.len}"
        else if val?field then "tcp option ${val.name} ${val.field}"
        else "tcp option ${val.name}";
      "ip option" =
        if val?field then "ip option ${val.name} ${val.field}"
        else "ip option ${val.name}";
      "sctp chunk" =
        if val?field then "sctp chunk ${val.name} ${val.field}"
        else "sctp chunk ${val.name}";
      meta =
        if notnft.metaKeys.${val.key}.unqualified or false then val.key
        else "meta ${val.key}";
      rt = optCat " " [ "rt" (val.family or null) val.key ];
      ct = optCat " " [ "ct" (val.dir or null) (val.family or null) val.key ];
      ipsec = optCat " " [ "ipsec" val.dir (optPre "spnum " (val.spnum or null)) (val.family or null) val.key ];
      numgen = optCat " " [ "numgen" val.mode "mod" val.mod (optPre "offset " (val.offset or null)) ];
      jhash = optCat " " [ "jhash" (compileExpr val.expr) "mod" val.mod (optPre "seed " (val.seed or null)) (optPre "offset " (val.offset or null)) ];
      symhash = optCat " " [ "symhash" val.mode "mod" val.mod (optPre "offset " (val.offset or null)) ];
      fib = let
          flags = if builtins.isList val.flags then cat " . " val.flags else val.flags;
        in "fib ${flags} ${val.result}";
      "|" = "(${compileExpr val.left}|${compileExpr val.right})";
      "&" = "(${compileExpr val.left}&${compileExpr val.right})";
      "^" = "(${compileExpr val.left}^${compileExpr val.right})";
      "<<" = "(${compileExpr val.left}<<${compileExpr val.right})";
      ">>" = "(${compileExpr val.left}>>${compileExpr val.right})";
      accept = "accept";
      drop = "drop";
      continue = "continue";
      return = "return";
      elem = optCat " " [ (compileExpr val.val) (optPre "timeout " (val.timeout or null)) (optPre "expires " (val.expires or null)) (optPre "comment " (mapStr compileExpr (val.comment or null))) ];
      socket = "socket ${val.key}";
      osf = optCat " " [ "osf" (optPre "ttl " val.ttl) val.key ];
    }.${key};

  compileStmt = x:
    if builtins.length (builtins.attrNames x) != 1 then throw "invalid attr count in statement with attrs ${cat ", " (builtins.attrNames x)}"
    else let key = builtins.head (builtins.attrNames x); val = x.${key}; in rec {
      accept = "accept";
      drop = "drop";
      continue = "continue";
      return = "return";
      jump = "jump ${compileStr val.target}";
      goto = "goto ${compileStr val.target}";
      match = optCat " " [ (mapStr compileExpr val.left) (if val.op == "in" then null else val.op) (mapStr compileExpr val.right) ];
      counter =
        if builtins.isNull val || (val?packets && val?bytes) then
          optCat " " [ "counter" (optPre "packets " (val.packets or null)) (optPre "bytes " (val.bytes or null)) ]
        else "counter name ${compileExpr val}";
      mangle = "${compileExpr val.key} set ${compileExpr val.value}";
      # quota [over/until] <num> <unit> [used <num>]
      quota =
        if val?val then
          optCat " " [ "quota" (if val.inv or false then "over" else "until") val.val val.val_unit (optPre "used ${val.used_unit or "bytes"}" val.used) ]
        else "quota name ${compileExpr val}";
      limit = "limit name ${compileExpr val}";
      fwd =
        if val?addr then
          "fwd to ${val.dev}"
        else optCat " " [ "fwd" val.family "to" val.addr "device" (compileStr val.dev) ];
      notrack = "notrack";
      snat = optCat " " [ key (optPre "to " (val.family or null)) val.addr (optPre ":" (val.port or null)) (mapStr compileExpr (val.flags or null)) ];
      dnat = snat;
      masquerade = optCat " " [ key (optPre "to :" (val.port or null)) (mapStr compileExpr (val.flags or null)) ];
      redirect = masquerade;
      reject = optCat " " [ "reject" (optPre "with " (val.type or null)) (mapStr compileExpr (val.expr or null)) ];
      set = throw "todo";
      log = throw "todo";
      "ct helper" = throw "todo";
      queue = throw "todo";
      vmap = throw "todo";
      "ct count" = throw "todo";
      "ct timeout" = throw "todo";
      "ct expectation" = throw "todo";
      xt = throw "todo";
      flow = throw "todo";
      tproxy = throw "todo";
      synproxy = throw "todo";
      reset = throw "todo";
      secmark = throw "todo";
    }.${key};

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
      
  compileCmd = cmd:
    if cmd?metainfo then "# ${builtins.toJSON cmd}"
    else let attr = lib.head (builtins.attrNames cmd); in "${attr} ${compileObject cmd.${attr}}";

  compileRuleset = { nftables }:
    cat "\n" (map compileCmd nftables);
}
