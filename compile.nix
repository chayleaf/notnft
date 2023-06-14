# compiles json into the nftables dsl
{ lib
, ... }:

let
  optPreSuf = pre: suf: x: if x != null && x != "" then "${pre}${toString x}${suf}" else "";
  optPre = pre: optPreSuf pre "";
  opt = optPreSuf "" "";
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
  compileExpr = x:
    if builtins.isString x && lib.hasPrefix "@" x then "@${compileStr (lib.removePrefix "@" x)}"
    else if builtins.isString x then compileStr x
    else if builtins.isPath x then compileStr (toString x)
    else if builtins.isInt x then toString x
    else if builtins.isBool x then (if x then "exists" else "missing")
    else if builtins.isFloat x then throw "nftables doesn't support floating point numbers"
    else if builtins.isNull x then throw "nftables doesn't support nulls"
    else if builtins.isFunction x then throw "nftables doesn't support functions"
    else if builtins.isList x then throw "how do you expect \"list expressions\" to work, please tell me so I can comprehend nftables's docs"
    else if x?concat then cat " . " (map compileExpr x.concat)
    else throw "todo";
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
