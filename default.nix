{ lib
, config ? {}
, ...
}:

/*
data types:
- int
  - conntrack direction :8
  - bitmask
    - conntrack state :4
    - conntrack status :4
    - conntrack event bits :4
    - conntrack label :128
  - lladdr (mac address?)
  - ipv4 (32bit)
  - ivp6 (128bit), may be enclosed in [] if has a port
  - bool (1bit: exists or missing)
  - icmp type (8bit)
  - icmp code type (8bit)
  - icmpv6 type (8bit)
  - icmpv6 code type (8bit)
- string
- list = { ",".join(members) }
*/

let
  cfg = config.notnftConfig or {};
  enumMode = cfg.enumMode or "normal";
  laxEnums = enumMode == "lax";
  strictEnums = enumMode == "strict";
  submodule' = { options, finalMerge ? lib.id, skipNulls ? true, freeformType ? null }:
  let
    reqFields = builtins.attrNames (if skipNulls then lib.filterAttrs (k: v: v.type.name != "nullOr") options else options);
    optFields = if skipNulls then builtins.attrNames (lib.filterAttrs (k: v: v.type.name == "nullOr") options) else [];
    reqFieldsDesc =
      if reqFields == [] then null
      else if builtins.length reqFields == 1 then ''field "${builtins.head reqFields}"''
      else "fields ${builtins.concatStringsSep ", " (map (x: ''"${x}"'') reqFields)}";
    optFieldsDesc =
      if optFields == [] then null
      else if builtins.length optFields == 1 then ''optional field "${builtins.head optFields}"''
      else "optional fields ${builtins.concatStringsSep ", " (map (x: ''"${x}"'') optFields)}";
  in
    submoduleWith' {
      shorthandOnlyDefinesConfig = true;
      modules = lib.toList ({
        inherit options;
      } // (if freeformType != null then {
        inherit freeformType;
      } else {}));
      description = "submodule with ${builtins.concatStringsSep " and " (builtins.filter builtins.isString [ reqFieldsDesc optFieldsDesc ])}";
      descriptionClass = "conjunction";
      chk = x: builtins.all (optName: x?${optName}) reqFields;
      inherit finalMerge skipNulls;
    };
  submoduleSK = key: val: submodule' {
    skipNulls = false;
    options.${key} = val;
  };
  submoduleWith' =
    { modules
    , specialArgs ? {}
    , shorthandOnlyDefinesConfig ? false
    , description ? null
    , descriptionClass ? "noun"
    , class ? null
    , finalMerge ? lib.id
    , skipNulls ? true
    , chk ? (_: true)
    }@attrs:
    let
      inherit (lib.modules) evalModules;

      allModules = defs: map ({ value, file }:
        if builtins.isAttrs value && shorthandOnlyDefinesConfig
        then { _file = file; config = value; }
        else { _file = file; imports = [ value ]; }
      ) defs;

      base = evalModules {
        inherit class specialArgs;
        modules = [{
          # This is a work-around for the fact that some sub-modules,
          # such as the one included in an attribute set, expects an "args"
          # attribute to be given to the sub-module. As the option
          # evaluation does not have any specific attribute name yet, we
          # provide a default for the documentation and the freeform type.
          #
          # This is necessary as some option declaration might use the
          # "name" attribute given as argument of the submodule and use it
          # as the default of option declarations.
          #
          # We use lookalike unicode single angle quotation marks because
          # of the docbook transformation the options receive. In all uses
          # &gt; and &lt; wouldn't be encoded correctly so the encoded values
          # would be used, and use of `<` and `>` would break the XML document.
          # It shouldn't cause an issue since this is cosmetic for the manual.
          _module.args.name = lib.mkOptionDefault "‹name›";
        }] ++ modules;
      };

      freeformType = base._module.freeformType;

      name = "submodule'";

    in lib.mkOptionType {
      inherit name descriptionClass;
      description =
        if description != null then description
        else freeformType.description or name;
      check = x: builtins.isAttrs x && chk x;
      merge = loc: defs:
        finalMerge ((if skipNulls then lib.filterAttrs (k: v: !(builtins.isNull v)) else lib.id) (base.extendModules {
          modules = [ { _module.args.name = lib.last loc; } ] ++ allModules defs;
          prefix = loc;
        }).config);
      emptyValue = { value = {}; };
      getSubOptions = prefix: (base.extendModules
        { inherit prefix; }).options // lib.optionalAttrs (freeformType != null) {
          # Expose the sub options of the freeform type. Note that the option
          # discovery doesn't care about the attribute name used here, so this
          # is just to avoid conflicts with potential options from the submodule
          _freeformOptions = freeformType.getSubOptions prefix;
        };
      getSubModules = modules;
      substSubModules = m: submoduleWith' (attrs // {
        modules = m;
      });
      nestedTypes = lib.optionalAttrs (freeformType != null) {
        freeformType = freeformType;
      };
      functor = lib.types.defaultFunctor name // {
        type = submoduleWith';
        payload = {
          inherit modules class specialArgs shorthandOnlyDefinesConfig description;
        };
        binOp = lhs: rhs: {
          class =
            # `or null` was added for backwards compatibility only. `class` is
            # always set in the current version of the module system.
            if lhs.class or null == null then rhs.class or null
            else if rhs.class or null == null then lhs.class or null
            else if lhs.class or null == rhs.class then lhs.class or null
            else throw "A submoduleWith' option is declared multiple times with conflicting class values \"${toString lhs.class}\" and \"${toString rhs.class}\".";
          modules = lhs.modules ++ rhs.modules;
          specialArgs =
            let intersecting = builtins.intersectAttrs lhs.specialArgs rhs.specialArgs;
            in if intersecting == {}
            then lhs.specialArgs // rhs.specialArgs
            else throw "A submoduleWith' option is declared multiple times with the same specialArgs \"${toString (builtins.attrNames intersecting)}\"";
          shorthandOnlyDefinesConfig =
            if lhs.shorthandOnlyDefinesConfig == null
            then rhs.shorthandOnlyDefinesConfig
            else if rhs.shorthandOnlyDefinesConfig == null
            then lhs.shorthandOnlyDefinesConfig
            else if lhs.shorthandOnlyDefinesConfig == rhs.shorthandOnlyDefinesConfig
            then lhs.shorthandOnlyDefinesConfig
            else throw "A submoduleWith' option is declared multiple times with conflicting shorthandOnlyDefinesConfig values";
          description =
            if lhs.description == null
            then rhs.description
            else if rhs.description == null
            then lhs.description
            else if lhs.description == rhs.description
            then lhs.description
            else throw "A submoduleWith' option is declared multiple times with conflicting descriptions";
        };
      };
    };

  oneOf = { name, description, descriptionClass ? "noun", types }: lib.types.mkOptionType rec {
    inherit name description descriptionClass;
    check = x: builtins.any (type: type.check x) types;
    nestedTypes = builtins.listToAttrs (lib.imap0 (i: x: { name = toString i; value = x; }) types);
    typeMerge = null;
    merge = loc: defs:
      let
        res = builtins.foldl'
          (x: type: if x != null then x else
            let val = builtins.tryEval (type.merge loc defs);
            in if val.success then val.value else x)
          null
          (builtins.filter (type: builtins.all ({ value, ... }: let ret = type.check value; in ret) defs) types);
      in
        if res == null
        then throw "The definition of option `${lib.showOption loc}` isn't a valid ${description}. Definition values:${lib.options.showDefs defs}"
        else res;
  };

  mkEnum = enum: builtins.mapAttrs (k: v: {
    __enum__ = enum;
    __value__ = k;
    __info__ = v;
    __toString = self: self.__value__;
  });
  types =
    let mkName = { name, description }: lib.mkOptionType {
      name = "${name}";
      description = "${description}";
      descriptionClass = "noun";
      check = x: builtins.isString x || (builtins.isAttrs x && x?name);
      merge = loc: defs: lib.mergeOneOption loc (map (def@{ value, ... }: def // {
        value =
          if builtins.isString value then value
          else if builtins.isAttrs value && value?name then value.name
          else throw "The definition of option `${lib.showOption loc}` isn't a valid ${description}. Definition values:${lib.options.showDefs defs}";
      }) defs);
    };
    mkNullOption = attrs: lib.mkOption (attrs // {
      default = null;
      type = lib.types.nullOr attrs.type;
    });
    mkEnum = { name, description, enum }: lib.mkOptionType {
      inherit name description;
      descriptionClass = "noun";
      check =
        let chk = x: builtins.isAttrs x && x?__toString && x?__value__ && x?__enum__ && (builtins.any (y: x.__value__ == y.__value__ && x.__enum__ == y.__enum__) (builtins.attrValues enum));
        in if strictEnums then chk
        else if laxEnums then (x: builtins.isString x || (builtins.isAttrs x && x?__toString))
        else (x: builtins.elem x (builtins.attrNames enum) || chk x);
      merge = loc: defs: lib.mergeOneOption loc (map (def: def // {
        value = toString def.value;
      }) defs);
    };
    mkTableType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = lib.mdDoc ''The table’s family, e.g. **"ip"** or **"ip6"**.'';
        };
        name = {
          type = lib.types.str;
          description = "The table’s name.";
        };
      } // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The table’s handle. In input, it is used only in **delete** command as alternative to **name**.";
        };
      } else {});
    };
    mkChainType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withNewName ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The chain's name.";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        type = {
          type = types.chainType;
          description = "The chain’s type.";
        };
        hook = {
          type = types.hook;
          description = "The chain’s hook.";
        };
        prio = {
          type = types.prio;
          description = "The chain’s priority.";
        };
        dev = {
          type = lib.types.str;
          description = "The chain’s bound interface (if in the netdev family).";
        };
        policy = {
          type = types.chainPolicy;
          description = "The chain’s policy.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The chain’s handle. In input, it is used only in **delete** command as alternative to **name**.";
        };
      } else {})
      // (if withNewName then builtins.mapAttrs mkOpt {
        newname = {
          type = lib.types.str;
          description = lib.mdDoc "A new name for the chain, only relevant in the **rename** command.";
        };
      } else {});
    };
    mkRuleType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withIndex ? false, withExpr ? false, withComment ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        chain = {
          type = types.chainName;
          description = "The chain's name.";
        };
      }
      // (if withExpr then builtins.mapAttrs mkOpt {
        expr = {
          type = lib.types.nonEmptyListOf types.statement;
          description = lib.mdDoc "An array of statements this rule consists of. In input, it is used in **add**/**insert**/**replace** commands only.";
        };
      } else {})
      // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The rule’s handle. In **delete**/**replace** commands, it serves as an identifier of the rule to delete/replace. In **add**/**insert** commands, it serves as an identifier of an existing rule to append/prepend the rule to.";
        };
      } else {})
      // (if withIndex then builtins.mapAttrs mkOpt {
        index = {
          type = lib.types.int;
          description = lib.mdDoc "The rule’s position for add/insert commands. It is used as an alternative to handle then.";
        };
      } else {})
      // (if withComment then builtins.mapAttrs mkOpt {
        comment = {
          type = lib.types.str;
          description = "Optional rule comment.";
        };
      } else {});
    };
    mkSetType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false, isMap ? null }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
      name = if isMap == true then "map" else "set";
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The ${name}'s name.";
        };
      } // (if withExtraFields then builtins.mapAttrs mkOpt {
        type = {
          type = lib.types.either (lib.types.nonEmptyListOf types.keyType) types.keyType;
          description = ''The ${name}’s datatype - might be a string, such as "ipv4_addr" or an array consisting of strings (for concatenated types).'';
        };
      } else {})
      // (if withExtraFields && isMap != false then builtins.mapAttrs mkOpt {
        map = {
          type = lib.types.either (lib.types.nonEmptyListOf types.valType) types.valType;
          description =
            if isMap == true then
              "Type of values this map maps to."
            else
              "Type of values this set maps to (i.e. this set is a map).";
        };
      } else {}) // (if withExtraFields then builtins.mapAttrs mkOpt {
        policy = {
          type = types.setPolicy;
          description = "The ${name}’s policy.";
        };
        flags = {
          type = lib.types.listOf types.setFlag;
          description = "The ${name}’s flags.";
        };
        elem = {
          type =
            if isMap == true then lib.types.listOf (types.listOfSize2 types.expression)
            else types.expression;
          description = lib.mdDoc ("Initial ${name} element(s)." + (lib.optionalString (isMap != false) " For mappings, an array of arrays with exactly two elements is expected."));
        };
        timeout = {
          type = lib.types.int;
          description = "Element timeout in seconds.";
        };
        gc-interval = {
          type = lib.types.int;
          description = "Garbage collector interval in seconds.";
        };
        size = {
          type = lib.types.int;
          description = "Maximum number of elements supported.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The set’s handle. For input, it is used in the **delete** command only.";
        };
      } else {});
    };
    mkElementType = { finalMerge ? lib.id, reqFields ? [], withElem ? false, isMap ? null }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
      name = if isMap == true then "map" else "set";
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = lib.mdDoc ''The table’s family, e.g. **"ip"** or **"ip6"**.'';
        };
        table = {
          type = types.tableName;
          description = "The table’s name.";
        };
        name = {
          type = if isMap == true then types.mapName else types.setName;
          description = "The ${name}’s name.";
        };
      } // (if withElem then builtins.mapAttrs mkOpt {
        elem = {
          type =
            if isMap == true then lib.types.listOf (types.listOfSize2 types.expression)
            else types.expression;
          description = lib.mdDoc ("Elements to add to the ${name}." + (lib.optionalString (isMap != false) " Use `[ key val ]` to specify a map element."));
        };
      } else {});
    };
    mkFlowtableType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The flowtable's name.";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        hook = {
          type = types.hook;
          description = "The flowtable’s hook.";
        };
        prio = {
          type = lib.types.int;
          description = "The flowtable’s priority.";
        };
        dev = {
          type = lib.types.either (lib.types.nonEmptyListOf lib.types.str) lib.types.str;
          description = "The flowtable’s interface(s).";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The flowtable’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCounterType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family.";
        };
        table = {
          type = types.tableName;
          description = "The table's name.";
        };
        name = {
          type = lib.types.str;
          description = "The counter's name.";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        packets = {
          type = lib.types.int;
          description = "Packet counter value.";
        };
        bytes = {
          type = lib.types.int;
          description = "Byte counter value.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The counter’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkQuotaType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The quota's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        bytes = {
          type = lib.types.int;
          description = "Quota threshold.";
        };
        used = {
          type = lib.types.int;
          description = "Quota used so far.";
        };
        inv = {
          type = lib.types.bool;
          default = false;
          description = "If true, match if the quota has been exceeded.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The quota’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCtHelperType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The ct helper's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        type = {
          type = lib.types.str;
          description = lib.mdDoc ''The ct helper type name, e.g. **"ftp"** or **"tftp"**.'';
        };
        protocol = {
          type = types.ctHelperL4Proto;
          description = "The ct helper’s layer 4 protocol.";
        };
        l3proto = {
          type = types.l3Proto;
          description = lib.mdDoc ''The ct helper's layer 3 protocol, e.g. **"ip"** or **"ip6"**.'';
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The ct helper’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkLimitType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The limit's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        rate = {
          type = lib.types.int;
          description = "The limit’s rate value.";
        };
        per = {
          type = types.timeUnit;
          description = lib.mdDoc ''Time unit to apply the limit to, e.g. **"week"**, **"day"**, **"hour"**, etc. If omitted, defaults to **"second"**.'';
          defaultText = lib.literalExpression "second";
        };
        burst = {
          type = lib.types.int;
          description = lib.mdDoc "The limit’s burst value. If omitted, defaults to **0**.";
          defaultText = lib.literalExpression 0;
        };
        unit = {
          type = types.rateUnit;
          description = lib.mdDoc ''Unit of rate and burst values. If omitted, defaults to **"packets"**.'';
          defaultText = lib.literalExpression "packets";
        };
        inv = {
          type = lib.types.bool;
          description = lib.mdDoc "If true, match if limit was exceeded. If omitted, defaults to **false**.";
          defaultText = lib.literalExpression false;
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The limit’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCtTimeoutType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The ct timeout object's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        protocol = {
          type = types.ctHelperL4Proto;
          description = "The ct timeout object’s layer 4 protocol.";
        };
        state = {
          type = types.connectionState;
          description = lib.mdDoc ''The connection state name, e.g. **"established"**, **"syn_sent"**, **"close"** or **"close_wait"**, for which the timeout value has to be updated.'';
        };
        value = {
          type = lib.types.int;
          description = "The updated timeout value for the specified connection state.";
        };
        l3proto = {
          type = types.l3Proto;
          description = lib.mdDoc ''The ct timeout object's layer 3 protocol, e.g. **"ip"** or **"ip6"**.'';
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The ct timeout object’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
    mkCtExpectationType = { finalMerge ? lib.id, reqFields ? [], withHandle ? false, withExtraFields ? false }:
    let
      req = x: builtins.elem x reqFields;
      mkOpt = x: if req x then lib.mkOption else mkNullOption;
    in submodule' {
      inherit finalMerge;
      options = builtins.mapAttrs mkOpt {
        family = {
          type = types.family;
          description = "The table's family";
        };
        table = {
          type = types.tableName;
          description = "The table's name";
        };
        name = {
          type = lib.types.str;
          description = "The ct expectation object's name";
        };
      }
      // (if withExtraFields then builtins.mapAttrs mkOpt {
        l3proto = {
          type = types.l3Proto;
          description = lib.mdDoc ''The ct expectation object's layer 3 protocol, e.g. **"ip"** or **"ip6"**.'';
        };
        protocol = {
          type = types.ctHelperL4Proto;
          description = "The ct expectation object’s layer 4 protocol.";
        };
        dport = {
          type = lib.types.int;
          description = "The destination port of the expected connection.";
        };
        timeout = {
          type = lib.types.int;
          description = "The time in millisecond that this expectation will live.";
        };
        size = {
          type = lib.types.int;
          description = "The maximum count of expectations to be living in the same time.";
        };
      } else {}) // (if withHandle then builtins.mapAttrs mkOpt {
        handle = {
          type = lib.types.int;
          description = lib.mdDoc "The ct expectation object’s handle. In input, it is used by the **delete** command only.";
        };
      } else {});
    };
  in {
    listOfSize2 = elemType:
      let list = lib.types.addCheck (lib.types.listOf elemType) (l: builtins.length l == 2);
      in list // {
        description = "${lib.types.optionDescriptionPhrase (class: class == "noun") list} of size 2 (key-value pair)";
        emptyValue = { }; # no .value attr, meaning unset
      };
    keyType = mkEnum {
      name = "nftablesKeyType";
      description = "nftables key type";
      enum = lib.filterAttrs (k: v: v.__info__.isKey or false) nftTypes;
    };
    valType = mkEnum {
      name = "nftablesValType";
      description = "nftables val type";
      enum = nftTypes;
    };
    family = mkEnum {
      name = "nftablesFamily";
      description = "nftables family";
      enum = families;
    };
    ipFamily = mkEnum {
      name = "nftablesIpFamily";
      description = "nftables ip family";
      enum = lib.filterAttrs (k: v: v.__info__.isIp or false) families;
    };
    chainType = mkEnum {
      name = "nftablesChainType";
      description = "nftables chain type";
      enum = chainTypes;
    };
    chainPolicy = mkEnum {
      name = "nftablesChainPolicy";
      description = "nftables chain policy";
      enum = chainPolicies;
    };
    setPolicy = mkEnum {
      name = "nftablesSetPolicy";
      description = "nftables set policy";
      enum = setPolicies;
    };
    setFlag = mkEnum {
      name = "nftablesSetFlag";
      description = "nftables set flag";
      enum = setFlags;
    };
    natFlag = mkEnum {
      name = "nftablesNatFlag";
      description = "nftables nat flag";
      enum = natFlags;
    };
    logLevel = mkEnum {
      name = "nftablesLogLevel";
      description = "nftables log level";
      enum = logLevels;
    };
    logFlag = mkEnum {
      name = "nftablesLogFlag";
      description = "nftables log flag";
      enum = logFlags;
    };
    queueFlag = mkEnum {
      name = "nftablesQueueFlag";
      description = "nftables queue flag";
      enum = queueFlags;
    };
    tableName = mkName {
      name = "nftablesTableName";
      description = "nftables table name";
    };
    chainName = mkName {
      name = "nftablesChainName";
      description = "nftables chain name";
    };
    counterName = mkName {
      name = "nftablesCounterName";
      description = "nftables counter name";
    };
    setName = mkName {
      name = "nftablesSetName";
      description = "nftables set name";
    };
    setReference = lib.types.mkOptionType rec {
      name = "nftablesSetReference";
      description = "nftables set reference";
      descriptionClass = "noun";
      merge = loc: defs: lib.mergeOneOption loc (map (def:
        if builtins.isString def && lib.hasPrefix "@" def then def
        else if builtins.isAttrs def && def?name then "@${def.name}"
        else throw "The definition of option `${lib.showOption loc}` isn't a valid ${description}. Definition values:${lib.options.showDefs defs}") defs);
    };
    mapName = mkName {
      name = "nftablesMapName";
      description = "nftables map name";
    };
    quotaName = mkName {
      name = "nftablesQuotaName";
      description = "nftables quota name";
    };
    hook = mkEnum {
      name = "nftablesHook";
      description = "nftables hook";
      enum = hooks;
    };
    prio = lib.mkOptionType {
      name = "nftablesPrio";
      description = "nftables chain priority";
      descriptionClass = "noun";
      check =
        x:
        builtins.isInt x
        || (if strictEnums then builtins.elem x (builtins.attrValues priorities)
            else builtins.elem x (builtins.attrNames priorities) || builtins.elem x (builtins.attrValues priorities));
      merge = loc: defs: lib.mergeOneOption loc (map (def: def // {
        value = if builtins.isInt def.value then def.value else toString def.value;
      }) defs);
    };
    ctHelperL4Proto = mkEnum {
      name = "nftablesCtHelperL4Proto";
      description = "nftables CT helper L4 protocol";
      enum = lib.filterAttrs (x: builtins.isAttrs x && builtins.isAttrs (x.__info__ or {}) && (x.__info__ or {}).inCtHelper or false) l4protocols;
    };
    l4Proto = mkEnum {
      name = "nftablesL4Proto";
      description = "nftables layer 4 protocol";
      enum = l4protocols;
    };
    l3Proto = mkEnum {
      name = "nftablesL3Proto";
      description = "nftables layer 3 protocol";
      enum = l3protocols;
    };
    timeUnit = mkEnum {
      name = "nftablesTimeUnit";
      description = "nftables time unit";
      enum = timeUnits;
    };
    byteUnit = mkEnum {
      name = "nftablesByteUnit";
      description = "nftables byte unit";
      enum = lib.filterAttrs (k: v: !v.__info__?onlyRate) byteUnits;
    };
    rateUnit = mkEnum {
      name = "nftablesByteUnit";
      description = "nftables byte unit";
      enum = byteUnits;
    };
    connectionState = mkEnum {
      name = "nftablesConnectionState";
      description = "nftables connection state";
      enum = connectionStates;
    };
    operator = mkEnum {
      name = "nftablesOperators";
      description = "nftables operator";
      enum = operators;
    };
    rejectType = mkEnum {
      name = "nftablesRejectType";
      description = "nftables reject type";
      enum = rejectTypes;
    };
    setOperator = mkEnum {
      name = "nftablesSetOperator";
      description = "nftables set operator";
      enum = setOperators;
    };
    xtType = mkEnum {
      name = "nftablesXtType";
      description = "nftables xt type";
      enum = xtTypes;
    };
    payloadBase = mkEnum {
      name = "nftablesPayloadBase";
      description = "nftables payload base";
      enum = payloadBases;
    };
    metaKey = mkEnum {
      name = "nftablesMetaKey";
      description = "nftables meta key";
      enum = metaKeys;
    };
    rtKey = mkEnum {
      name = "nftablesRtKey";
      description = "nftables routing data key";
      enum = rtKeys;
    };
    ctDir = mkEnum {
      name = "nftablesCtDir";
      description = "nftables ct direction";
      enum = ctDirs;
    };
    ngMode = mkEnum {
      name = "nftablesNgMode";
      description = "nftables numgen mode";
      enum = ngModes;
    };
    fibResult = mkEnum {
      name = "nftablesFibResult";
      description = "nftables fib type";
      enum = fibResults;
    };
    fibFlag = mkEnum {
      name = "nftablesFibFlag";
      description = "nftables fib flag";
      enum = fibFlags;
    };
    socketKey = mkEnum {
      name = "nftablesSocketKey";
      description = "nftables socket key";
      enum = socketKeys;
    };
    osfKey = mkEnum {
      name = "nftablesOsfKey";
      description = "nftables osf key";
      enum = osfKeys;
    };
    osfTtl = mkEnum {
      name = "nftablesOsfTtl";
      description = "nftables osf ttl";
      enum = osfTtl;
    };
    payloadProtocol = mkEnum {
      name = "nftablesPayloadProtocol";
      description = "nftables payload protocol";
      enum = payloadProtocols;
    };
    payloadField = mkEnum {
      name = "nftablesPayloadField";
      description = "nftables payload field";
      enum = payloadFields;
    };
    exthdr = mkEnum {
      name = "nftablesExthdr";
      description = "nftables ipv6 extension header";
      enum = exthdrs;
    };
    exthdrField = mkEnum {
      name = "nftablesExthdrField";
      description = "nftables ipv6 extension header field";
      enum = exthdrFields;
    };
    tcpOption = mkEnum {
      name = "nftablesTcpOption";
      description = "nftables tcp option";
      enum = tcpOptions;
    };
    tcpOptionField = mkEnum {
      name = "nftablesTcpOptionField";
      description = "nftables tcp option field";
      enum = tcpOptionFields;
    };
    sctpChunk = mkEnum {
      name = "nftablesSctpChunk";
      description = "nftables sctp chunk";
      enum = sctpChunks;
    };
    sctpChunkField = mkEnum {
      name = "nftablesSctpChunkField";
      description = "nftables sctp chunk field";
      enum = sctpChunkFields;
    };
    ctKey = mkEnum {
      name = "nftablesCtKey";
      description = "nftables ct expression key";
      enum = ctKeys;
    };
    tableToDelete = mkTableType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ ];
      withHandle = true;
    };
    # anything but delete
    tableToWhatever = mkTableType { reqFields = [ "name" ]; };
    chainToAdd = mkChainType {
      finalMerge = x:
        let
          baseDetect = [ "type" "hook" "prio" "policy" "dev" ];
          reqBase = [ "type" "hook" "prio" "policy" ];
          familyInfo = (families.${x.family or ""} or {}).__info__ or {};
          reqBase' = reqBase ++ (lib.optionals (familyInfo.requireBaseChainDevice or false) [ "dev" ]);
          info = (chainTypes.${x.type or ""} or {}).__info__ or {};
        in
          if
            builtins.any (k: builtins.elem k baseDetect) (builtins.attrNames x)
            && builtins.any (k: !x?${k}) reqBase'
          then
            throw "Base chains ${
              if x.family or "" == "netdev" then "in the netdev family " else ""
            }must have fields ${builtins.concatStringsSep ", " (map (s: "`${s}`") reqBase')} set"
          else if x.family or "" != "netdev" && x?dev then
            throw "I'm not sure about this, but I think non-netdev family chains can't have a device specified, check your code or open an issue!"
          else if x?family && info.families or null != null && !(builtins.elem x.family info.families) then
            throw "Chains of type ${x.type} can only be in families ${builtins.concatStringsSep ", " info.families}"
          else if x?hook && info.hooks or null != null && !(builtins.elem x.hook info.hooks) then
            throw "Chains of type ${x.type} can only be in hooks ${builtins.concatStringsSep ", " info.hooks}"
          else if x?hook && familyInfo.hooks or null != null && !(builtins.elem x.hook familyInfo.hooks) then
            throw "Chains of family ${x.family} can only be in hooks ${builtins.concatStringsSep ", " familyInfo.hooks}"
          else
            x // (if builtins.isString (x.prio or null) then
              let
                prioInfo = priorities.${x.prio}.__info__;
              in
                (if x?family && prioInfo.families or null != null && !(builtins.elem x.family prioInfo.families) then
                  throw "Priority ${x.prio} can only be used in families ${builtins.concatStringsSep ", " prioInfo.families}"
                else if x?hook && prioInfo.hooks or null != null && !(builtins.elem x.hook prioInfo.hooks) then
                  throw "Priority ${x.prio} can only be used in hooks ${builtins.concatStringsSep ", " prioInfo.hooks}"
                else {
                  prio = prioInfo.value (x.family or "");
                })
            else {});
      reqFields = [ "table" "name" ];
      withExtraFields = true;
    };
    chainToDelete = mkChainType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      withHandle = true;
      reqFields = [ "table" ];
    };
    chainToRename = mkChainType {
      withNewName = true;
      reqFields = [ "table" "name" "newname" ];
    };
    # anything but add/delete/rename
    chainToWhatever = mkChainType {
      reqFields = [ "table" "name" ];
    };
    ruleToAdd = mkRuleType {
      reqFields = [ "table" "chain" "expr" ];
      withExpr = true;
      withHandle = true;
      withIndex = true;
      withComment = true;
    };
    ruleToReplace = mkRuleType {
      reqFields = [ "table" "chain" "handle" "expr" ];
      withExpr = true;
      withHandle = true;
      withComment = true;
    };
    # anything but add/replace
    ruleToWhatever = mkRuleType {
      reqFields = [ "table" "chain" "handle" ];
      withHandle = true;
    };
    setToAdd = mkSetType {
      isMap = false;
      reqFields = [ "table" "name" "type" ];
      withExtraFields = true;
    };
    setToDelete = mkSetType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      withHandle = true;
      isMap = false;
      reqFields = [ "table" ];
    };
    # anything but add/delete
    setToWhatever = mkSetType {
      isMap = false;
      reqFields = [ "table" "name" ];
    };
    mapToAdd = mkSetType {
      isMap = true;
      reqFields = [ "table" "name" "type" ];
      withExtraFields = true;
    };
    mapToDelete = mkSetType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      withHandle = true;
      isMap = true;
      reqFields = [ "table" ];
    };
    # anything but add/delete
    mapToWhatever = mkSetType {
      isMap = true;
      reqFields = [ "table" "name" ];
    };
    elementToAdd = mkElementType {
      reqFields = [ "table" "name" "elem" ];
      withElem = true;
    };
    # anything but add
    elementToWhatever = mkElementType {
      reqFields = [ "table" "name" ];
    };
    setElementToAdd = mkElementType {
      reqFields = [ "table" "name" "elem" ];
      withElem = true;
      isMap = false;
    };
    # anything but add
    setElementToWhatever = mkElementType {
      reqFields = [ "table" "name" ];
      isMap = false;
    };
    mapElementToAdd = mkElementType {
      reqFields = [ "table" "name" "elem" ];
      withElem = true;
      isMap = true;
    };
    # anything but add
    mapElementToWhatever = mkElementType {
      reqFields = [ "table" "name" ];
      isMap = true;
    };
    flowtableToAdd = mkFlowtableType {
      reqFields = [ "table" "name" "hook" "prio" "dev" ];
      withExtraFields = true;
    };
    flowtableToDelete = mkFlowtableType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    # anything but add/delete
    flowTableToWhatever = mkFlowtableType {
      reqFields = [ "table" "name" ];
    };
    counterToAdd = mkCounterType {
      reqFields = [ "table" "name" ];
      withExtraFields = true;
    };
    counterToDelete = mkCounterType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    counterToWhatever = mkCounterType {
      reqFields = [ "table" "name" ];
    };
    quotaToAdd = mkQuotaType {
      reqFields = [ "table" "name" "bytes" "inv" ];
      withExtraFields = true;
    };
    quotaToDelete = mkQuotaType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    quotaToWhatever = mkQuotaType {
      reqFields = [ "table" "name" ];
    };
    ctHelperToAdd = mkCtHelperType {
      reqFields = [ "table" "name" "type" "protocol" ];
      withExtraFields = true;
    };
    ctHelperToDelete = mkCtHelperType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    ctHelperToWhatever = mkCtHelperType {
      reqFields = [ "table" "name" ];
    };
    limitToAdd = mkLimitType {
      reqFields = [ "table" "name" "type" "rate" ];
      withExtraFields = true;
    };
    limitToDelete = mkLimitType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    limitToWhatever = mkLimitType {
      reqFields = [ "table" "name" ];
    };
    ctTimeoutToAdd = mkCtTimeoutType {
      reqFields = [ "table" "name" "type" "protocol" "state" "value" ];
      withExtraFields = true;
    };
    ctTimeoutToDelete = mkCtTimeoutType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    ctTimeoutToWhatever = mkCtTimeoutType {
      reqFields = [ "table" "name" ];
    };
    ctExpectationToAdd = mkCtExpectationType {
      reqFields = [ "table" "name" "protocol" "dport" "timeout" "size" ];
      withExtraFields = true;
    };
    ctExpectationToDelete = mkCtExpectationType {
      finalMerge = x:
        if !x?handle && !x?name then throw "Handle or name to be deleted must be specified"
        else if x?handle && x?name then throw "Only one of handle or name to be deleted must be specified"
        else x;
      reqFields = [ "table" ];
      withHandle = true;
    };
    ctExpectationToWhatever = mkCtExpectationType {
      reqFields = [ "table" "name" ];
    };
    addCommand = oneOf {
      name = "nftablesAddCommand";
      description = "add command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = v;
        description = "Add ${k}.";
      })) {
        table = types.tableToWhatever;
        chain = types.chainToAdd;
        rule = types.ruleToAdd;
        set = types.setToAdd;
        map = types.mapToAdd;
        element = types.elementToAdd;
        flowtable = types.flowtableToAdd;
        counter = types.counterToAdd;
        quota = types.quotaToAdd;
        "ct helper" = types.ctHelperToAdd;
        limit = types.limitToAdd;
        "ct timeout" = types.ctTimeoutToAdd;
        "ct expectation" = types.ctExpectationToAdd;
      };
    };
    replaceCommand = lib.types.submodule {
      options = {
        rule = lib.mkOption {
          type = types.ruleToReplace;
          description = "rule to replace";
        };
      };
    };
    createCommand = oneOf {
      name = "nftablesCreateCommand";
      description = "nftables create command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = v;
        description = "Create ${k} (same as add, but ensure it doesn't already exist).";
      })) {
        table = types.tableToWhatever;
        chain = types.chainToAdd;
        rule = types.ruleToAdd;
        set = types.setToAdd;
        map = types.mapToAdd;
        element = types.elementToAdd;
        flowtable = types.flowtableToAdd;
        counter = types.counterToAdd;
        quota = types.quotaToAdd;
        "ct helper" = types.ctHelperToAdd;
        limit = types.limitToAdd;
        "ct timeout" = types.ctTimeoutToAdd;
        "ct expectation" = types.ctExpectationToAdd;
      };
    };
    insertCommand = lib.types.submodule {
      options = {
        rule = lib.mkOption {
          type = types.ruleToReplace;
          description = "rule to insert (prepend)";
        };
      };
    };
    deleteCommand = oneOf {
      name = "nftablesDeleteCommand";
      description = "nftables delete command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = v;
        description = "Delete ${k}.";
      })) {
        table = types.tableToDelete;
        chain = types.chainToDelete;
        rule = types.ruleToWhatever;
        set = types.setToDelete;
        map = types.mapToDelete;
        element = types.elementToWhatever;
        flowtable = types.flowtableToDelete;
        counter = types.counterToDelete;
        quota = types.quotaToDelete;
        "ct helper" = types.ctHelperToDelete;
        limit = types.limitToDelete;
        "ct timeout" = types.ctTimeoutToDelete;
        "ct expectation" = types.ctExpectationToDelete;
      };
    };
    null = lib.mkOptionType {
      name = "null";
      descriptionClass = "noun";
      check = x: x == null;
      merge = loc: defs: null;
      emptyValue = { value = null; };
    };
    listCommand = oneOf {
      name = "nftablesListCommand";
      description = "nftables list command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = v;
        description = "List ${k}.";
      })) {
        table = types.tableToWhatever;
        tables = types.null;
        chain = types.chainToWhatever;
        chains = types.null;
        set = types.setToWhatever;
        sets = types.null;
        map = types.mapToWhatever;
        maps = types.null;
        counter = types.counterToWhatever;
        counters = types.null;
        quota = types.quotaToWhatever;
        quotas = types.null;
        "ct helper" = types.ctHelperToWhatever;
        "ct helpers" = types.null;
        limit = types.limitToWhatever;
        limits = types.null;
        ruleset = types.null;
        meter = types.meterToWhatever;
        meters = types.null;
        flowtable = types.flowtableToWhatever;
        flowtables = types.null;
        "ct timeout" = types.ctTimeoutToWhatever;
        "ct timeouts" = types.null;
        "ct expectation" = lib.types.either types.null types.ctExpectationToWhatever;
      };
    };
    resetCommand = oneOf {
      name = "nftablesListCommand";
      description = "nftables list command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = v;
        description = "Reset ${k}.";
      })) {
        counter = types.counterToWhatever;
        counters = types.null;
        quota = types.quotaToWhatever;
        quotas = types.null;
        rule = types.ruleToWhatever;
        rules = types.null;
      };
    };
    flushCommand = oneOf {
      name = "nftablesListCommand";
      description = "nftables list command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        type = v;
        description = "Flush ${k}.";
      })) {
        table = types.tableToWhatever;
        chain = types.chainToWhatever;
        set = types.setToWhatever;
        map = types.mapToWhatever;
        meter = types.meterToWhatever;
        ruleset = types.null;
      };
    };
    renameCommand = lib.types.submodule {
      options = {
        rule = lib.mkOption {
          type = types.chainToRename;
          description = "chain to rename";
        };
      };
    };
    command = oneOf {
      name = "nftablesCommand";
      description = "nftables command";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} command.\n\n${v.description}";
      })) {
        add = {
          type = types.addCommand;
          description = "Add a new ruleset element to the kernel.";
        };
        replace = {
          type = types.replaceCommand;
          description = lib.mdDoc "Replace a rule. In rule, the **handle** property is mandatory and identifies the rule to be replaced.";
        };
        create = {
          type = types.createCommand;
          description = lib.mdDoc "Identical to **add** command, but returns an error if the object already exists.";
        };
        insert = {
          type = types.insertCommand ;
          description = lib.mdDoc "This command is identical to **add** for rules, but instead of appending the rule to the chain by default, it inserts at first position. If a **handle** or **index** property is given, the rule is inserted before the rule identified by those properties.";
        };
        delete = {
          type = types.deleteCommand;
          description = lib.mdDoc "Delete an object from the ruleset. Only the minimal number of properties required to uniquely identify an object is generally needed in *ADD_OBJECT*. For most ruleset elements, this is **family** and **table** plus either **handle** or **name** (except rules since they don’t have a name).";
        };
        list = {
          type = types.listCommand;
          description = lib.mdDoc "List ruleset elements. The plural forms are used to list all objects of that kind, optionally filtered by **family** and for some, also **table**.";
        };
        reset = {
          type = types.resetCommand;
          description = "Reset state in suitable objects, i.e. zero their internal counter.";
        };
        flush = {
          type = types.flushCommand;
          description = lib.mdDoc "Empty contents in given object, e.g. remove all chains from given **table** or remove all elements from given **set**.";
        };
        rename = {
          type = types.renameCommand;
          description = lib.mdDoc "Rename a chain. The new name is expected in a dedicated property named **newname**.";
        };
      };
    };
    # not really ruleset, just commands
    ruleset = lib.types.submodule {
      options.nftables = lib.mkOption {
        type = lib.types.listOf types.command;
        description = "Commands to execute.";
        default = [ ];
      };
    };
    # next: Statements
    jumpStatement = lib.types.submodule {
      options.target = lib.mkOption { type = types.chainName; description = "jump target"; };
    };
    jumpExpression = types.jumpStatement;
    gotoStatement = lib.types.submodule {
      options.target = lib.mkOption { type = types.chainName; description = "goto target"; };
    };
    gotoExpression = types.gotoStatement;
    matchStatement = lib.types.submodule {
      options.left = lib.mkOption { type = types.expression; description = "Left hand side of this match."; };
      options.right = lib.mkOption { type = types.expression; description = "Right hand side of this match."; };
      options.op = lib.mkOption { type = types.operator; description = "Operator indicating the type of comparison."; };
    };
    counterStatement = lib.types.submodule {
      options.packets = lib.mkOption {
        type = lib.types.int;
        description = "Packets counted";
      };
      options.bytes = lib.mkOption {
        type = lib.types.int;
        description = "Byte counter value.";
      };
    };
    mangleStatement = submodule' {
      finalMerge = x:
        if x.key?exthdr || x.key?payload || x.key?meta || x.key?ct || x.key?"ct helper" then x
        else throw ''Key must be given as an "exthdr", "payload", "meta", "ct" or "ct helper" expression.'';
      options.key = lib.mkOption {
        type = types.expression;
        description = lib.mdDoc "The packet data to be changed, given as an **exthdr**, **payload**, **meta**, **ct** or **ct helper** expression.";
      };
      options.value = lib.mkOption {
        type = types.expression;
        description = "Value to change data to.";
      };
    };
    quotaStatement = lib.types.either lib.types.str (submodule' {
      options.val = lib.mkOption {
        type = lib.types.int;
        description = "Quota value.";
      };
      options.val_unit = lib.mkOption {
        type = types.byteUnit;
        description = lib.mdDoc ''Unit of **val**, e.g. **"kbytes"** or **"mbytes"**. If omitted, defaults to **"bytes"**.'';
        defaultText = lib.literalExpression "bytes";
      };
      options.used = mkNullOption {
        type = types.int;
        description = "Quota used so far. Optional on input. If given, serves as initial value.";
      };
      options.used_unit = mkNullOption {
        type = types.byteUnit;
        description = lib.mdDoc ''Unit of **used**. Defaults to **"bytes"**.'';
        defaultText = lib.literalExpression "bytes";
      };
      options.inv = mkNullOption {
        type = lib.types.bool;
        description = lib.mdDoc "If **true**, will match if the quota has been exceeded. Defaults to **false**.";
        defaultText = lib.literalExpression false;
      };
    });
    limitStatement = lib.types.either lib.types.str (submodule' {
      finalMerge = x: if (x.rate_unit or "packets") == "packets" && x?burst_unit then throw "burst_unit is ignored when rate_unit is \"packets\", don't set it" else x;
      options.rate = lib.mkOption {
        type = lib.types.int;
        description = "Rate value to limit to.";
      };
      options.rate_unit = mkNullOption {
        type = types.rateUnit;
        description = lib.mdDoc ''Unit of **rate**, e.g. **"packets"** or **"mbytes"**. Defaults to **"packets"**.'';
        defaultText = lib.literalExpression "packets";
      };
      options.per = lib.mkOption {
        type = types.timeUnit;
        description = lib.mdDoc ''Denominator of rate, e.g. **"week"** or **"minutes"**.'';
      };
      options.burst = mkNullOption {
        type = lib.types.int;
        description = lib.mdDoc "Burst value. Defaults to **0**.";
        defaultText = lib.literalExpression 0;
      };
      options.burst_unit = mkNullOption {
        type = types.byteUnit;
        description = lib.mdDoc ''Unit of burst, ignored if rate_unit is **"packets"**. Defaults to **"bytes"**.'';
        defaultText = lib.literalExpression "bytes";
      };
      options.inv = mkNullOption {
        type = lib.types.bool;
        description = lib.mdDoc "If **true**, matches if the limit was exceeded. Defaults to **false**.";
        defaultText = lib.literalExpression false;
      };
    });
    # TODO actually check
    ipAddr = lib.types.strMatching (x: true);
    fwdStatement = submodule' {
      finalMerge = x:
        if (x?family && !x?addr) || (x?addr && !x?family)
        then throw "If at least one of `addr` or `family` is given, both must be present."
        else x;
      options.dev = lib.mkOption {
        type = types.expression;
        description = "Interface to forward the packet on.";
      };
      options.family = mkNullOption {
        type = types.ipFamily;
        description = lib.mdDoc "Family of **addr**.";
      };
      options.addr = mkNullOption {
        type = types.ipAddr;
        description = "IP(v6) address to forward the packet to.";
      };
    };
    dupStatement = submodule' {
      finalMerge = x:
        if !x?addr && !x?dev
        then throw "At least one of `addr` or `dev` must be specified."
        else x;
      options.addr = mkNullOption {
        type = types.expression;
        description = "Address to duplicate packet to.";
      };
      options.dev = mkNullOption {
        type = types.expression;
        description = "Interface to duplicate packet on. May be omitted to not specify an interface explicitly.";
      };
    };
    snatStatement = submodule' {
      options.addr = mkNullOption {
        type = types.expression;
        description = "Address to translate to.";
      };
      options.family = mkNullOption {
        type = types.ipFamily;
        description = "Family of addr, either ip or ip6. Required in inet table family.";
      };
      options.port = mkNullOption {
        type = lib.types.int;
        description = "Port to translate to.";
      };
      options.flags = lib.mkOption {
        type = lib.types.listOf types.natFlag;
        description = "Flag(s).";
        default = [ ];
      };
    };
    dnatStatement = types.snatStatement;
    masqueradeStatement = submodule' {
      options.port = mkNullOption {
        type = lib.types.int;
        description = "Port to translate to.";
      };
      options.flags = mkNullOption {
        type = lib.types.listOf types.natFlag;
        description = "Flag(s).";
      };
    };
    redirectStatement = types.masqueradeStatement;
    rejectStatement = submodule' {
      finalMerge = x: if x.expr or null != null && x.type or null == "tcp reset" then throw "ICMP reject codes are only valid for rejections with type `icmp`/`icmpv6`/`icmpx`" else x;
      options.type = mkNullOption {
        type = types.rejectTypes;
        description = lib.mdDoc ''Type of reject, either **"tcp reset"**, **"icmpx"**, **"icmp"** or **"icmpv6"**.'';
      };
      options.expr = mkNullOption {
        type = types.expression;
        description = "ICMP code to reject with.";
      };
    };
    setStatement = lib.types.submodule {
      options.op = lib.mkOption {
        description = lib.mdDoc ''Operator on set, either **"add"** or **"update"**.'';
        type = types.setOperator;
      };
      options.elem = lib.mkOption {
        description = "Set element to add or update.";
        type = types.expression;
      };
      options.set = lib.mkOption {
        description = "Set reference.";
        type = types.setReference;
      };
    };
    logStatement = submodule' {
      options.prefix = mkNullOption {
        description = "Prefix for log entries.";
        type = lib.types.str;
      };
      options.group = mkNullOption {
        description = "Log group.";
        type = lib.types.int;
      };
      options.snaplen = mkNullOption {
        description = "Snaplen for logging.";
        type = lib.types.int;
      };
      options.queue-threshold = mkNullOption {
        description = "Queue threshold.";
        type = lib.types.int;
      };
      options.level = mkNullOption {
        description = lib.mdDoc ''Log level. Defaults to **"warn"**.'';
        type = types.logLevel;
        defaultText = lib.literalExpression "warn";
      };
      options.flags = lib.mkOption {
        description = "Log flags.";
        type = lib.types.listOf types.logFlag;
        default = [];
      };
    };
    meterStatement = lib.types.submodule {
      options.name = lib.mkOption {
        description = "Meter name.";
        type = lib.types.str;
      };
      options.key = lib.mkOption {
        description = "Meter key.";
        type = types.expression;
      };
      options.stmt = lib.mkOption {
        description = "Meter statement.";
        type = types.statement;
      };
    };
    queueStatement = lib.types.submodule {
      options.num = lib.mkOption {
        description = "Queue number.";
        type = types.expression;
      };
      options.flags = lib.mkOption {
        description = "Queue flags.";
        type = lib.types.listOf types.queueFlag;
      };
    };
    vmapStatement = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Map key.";
        type = types.expression;
      };
      options.data = lib.mkOption {
        description = "Mapping expression consisting of value/verdict pairs.";
        type = lib.types.listOf (types.listOfSize2 types.expression);
      };
    };
    ctCountStatement = submodule' {
      options.val = lib.mkOption {
        description = "Connection count threshold.";
        type = lib.types.int;
      };
      options.inv = mkNullOption {
        type = lib.types.bool;
        description = lib.mdDoc "If **true**, match if **val** was exceeded. If omitted, defaults to **false**.";
        defaultText = lib.literalExpression false;
      };
    };
    xtStatement = lib.types.submodule {
      options.type = lib.mkOption {
        type = types.xtType;
      };
      options.name = lib.mkOption {
        type = lib.types.str;
      };
    };
    statement = oneOf {
      name = "nftablesStatement";
      description = "nftables statement";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} statement.\n\n${v.description}";
      })) {
        # verdicts
        accept = {
          type = types.null; 
          description = "Terminate ruleset evaluation and accept the packet";
        };
        drop = {
          type = types.null;
          description = "Terminate ruleset evaluation and drop the packet.";
        };
        continue = {
          type = types.null;
          description = "Continue ruleset evaluation with the next rule.";
        };
        return = {
          type = types.null;
          description = "Return from the current chain and continue evaluation at the next rule in the last chain.";
        };
        jump = {
          type = types.jumpStatement;
          description = "Continue evaluation at the first rule in chain, pushing the current position to the call stack.";
        };
        goto = {
          type = types.gotoStatement;
          description = lib.mdDoc "Similar to **jump**, but the current position is not pushed to the call stack.";
        };
        match = {
          type = types.matchStatement;
          description = lib.mdDoc ''
            Unlike with the standard API, the operator is mandatory here. In the standard API, a missing operator may be resolved in two ways, depending on the type of expression on the RHS:

            - If the RHS is a bitmask or a list of bitmasks, the expression resolves into a binary operation with the inequality operator, like this: LHS & RHS != 0.
            - In any other case, the equality operator is simply inserted.

            For the non-trivial first case, the JSON API supports the in operator.
        '';
        };
        counter = {
          type = types.counterStatement;
          description = lib.mdDoc ''
            This object represents a byte/packet counter. In input, no properties are required. If given, they act as initial values for the counter.

            The first form creates an anonymous counter which lives in the rule it appears in. The second form specifies a reference to a named counter object.
          '';
        };
        mangle = {
          type = types.mangleStatement;
          description = "This changes the packet data or meta info.";
        };
        quota = {
          type = types.quotaStatement;
          description = "The first form creates an anonymous quota which lives in the rule it appears in. The second form specifies a reference to a named quota object.";
        };
        limit = {
          type = types.limitStatement;
          description = "The first form creates an anonymous quota which lives in the rule it appears in. The second form specifies a reference to a named quota object.";
        };
        fwd = {
          type = types.fwdStatement;
          description = "Forward a packet to a different destination.";
        };
        notrack = {
          type = types.null;
          description = "Disable connection tracking for the packet.";
        };
        dup = {
          type = types.dupStatement; 
          description = "Duplicate a packet to a different destination.";
        };
        # NAT
        snat = {
          type = types.snatStatement;
          description = "Perform Source Network Address Translation.";
        };
        dnat = {
          type = types.dnatStatement;
          description = "Perform Destination Network Address Translation.";
        };
        masquerade = {
          type = types.masqueradeStatement;
          description = "Perform Source Network Address Translation to the outgoing interface's IP address.";
        };
        redirect = {
          type = types.redirectStatement;
          description = "Perform Destination Network Address Translation to the local host's IP address.";
        };
        reject = {
          type = types.rejectStatement;
          description = "Reject the packet and send the given error reply.";
        };
        set = {
          type = types.setStatement;
          description = "Dynamically add/update elements to a set.";
        };
        log = {
          type = types.logStatement;
          description = "Log the packet.";
        };
        "ct helper" = {
          type = types.expression;
          description = "Enable the specified conntrack helper for this packet.";
        };
        meter = {
          type = types.meterStatement;
          description = "Apply a given statement using a meter.";
        };
        queue = {
          type = types.queueStatement;
          description = "Terminate ruleset evaluation and queue the packet to userspace.";
        };
        vmap = {
          type = types.vmapStatement;
          description = "Apply a verdict conditionally.";
        };
        "ct count" = {
          type = types.ctCountStatement;
          description = "Limit the number of connections using conntrack.";
        };
        "ct timeout" = {
          type = types.expression;
          description = "Assign connection tracking timeout policy.";
        };
        "ct expectation" = {
          type = types.expression;
          description = "Assign connection tracking expectation.";
        };
        xt = {
          type = types.xtStatement;
          description = lib.mdDoc ''
            This represents an xt statement from xtables compat interface. It is a fallback if translation is not available or not complete.

            Seeing this means the ruleset (or parts of it) were created by **iptables-nft** and one should use that to manage it.

            **BEWARE:** nftables won’t restore these statements.
          '';
        };
      };
    };
    rangeExpression = lib.types.either (types.listOfSize2 types.expression) (submodule' {
      finalMerge = { min, max }: [ min max ];
      options.min = lib.mkOption {
        description = "lower bound of a range";
        type = types.expression;
      };
      options.max = lib.mkOption {
        description = "upper bound of a range";
        type = types.expression;
      };
    });
    mapExpression = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Map key.";
        type = types.expression;
      };
      options.data = lib.mkOption {
        description = "Mapping expression consisting of value/target pairs.";
        type = types.expression;
      };
    };
    prefixExpression = lib.types.submodule {
      options.addr = lib.mkOption {
        description = "Address part of an address prefix.";
        type = types.expression;
      };
      options.len = lib.mkOption {
        description = "Prefix length.";
        type = lib.types.int;
      };
    };
    rawPayloadExpression = lib.types.submodule {
      options.base = lib.mkOption {
        description = "Payload base.";
        type = types.payloadBase;
      };
      options.offset = lib.mkOption {
        description = "Payload offset.";
        type = lib.types.int;
      };
      options.len = lib.mkOption {
        description = "Payload length.";
        type = lib.types.int;
      };
    };
    fieldPayloadExpression = submodule' {
      finalMerge = { protocol, field }@ret: let
        inherit (payloadProtocols.${protocol}.__info__) fields;
      in if laxEnums || builtins.elem field fields then ret else throw "Protocol ${protocol} only supports fields ${builtins.concatStringsSep ", " fields}";
      options.protocol = lib.mkOption {
        description = "Payload reference packet header protocol.";
        type = types.payloadProtocol;
      };
      options.field = lib.mkOption {
        description = "Payload reference packet header field.";
        type = types.payloadField;
      };
    };
    payloadExpression = oneOf {
      name = "nftablesPayloadExpression";
      description = "nftables payload expression";
      types = [ types.rawPayloadExpression types.fieldPayloadExpression ];
    };
    exthdrExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (exthdrs.${name}.__info__) fields;
      in if laxEnums || !ret?field || builtins.elem ret.field fields then ret else throw "IPv6 extension header ${name} only supports fields ${builtins.concatStringsSep ", " fields}";
      options.name = lib.mkOption {
        description = "IPv6 extension header name.";
        type = types.exthdr;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "Field name. If this property is not given, the expression is to be used as a header existence check in a **match** statement with a boolean on the right hand side.";
        type = types.exthdrField;
      };
      options.offset = mkNullOption {
        description = lib.mdDoc "Field **offset** (used only for **rt0** protocol).";
        type = lib.types.int;
      };
    };
    tcpOptionExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (tcpOptions.${name}.__info__) fields;
      in if laxEnums || !ret?field || builtins.elem ret.field fields then ret else throw "TCP option ${name} only supports fields ${builtins.concatStringsSep ", " fields}";
      options.name = lib.mkOption {
        description = "TCP option header name.";
        type = types.tcpOption;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "TCP option header field. If this property is not given, the expression is to be used as a TCP option existence check in a **match** statement with a boolean on the right hand side.";
        type = types.tcpOptionField;
      };
    };
    sctpChunkExpression = submodule' {
      finalMerge = { name, ... }@ret: let
        inherit (sctpChunks.${name}.__info__) fields;
      in if laxEnums || !ret?field || builtins.elem ret.field fields then ret else throw "SCTP chunk ${name} only supports fields ${builtins.concatStringsSep ", " fields}";
      options.name = lib.mkOption {
        description = "SCTP chunk name.";
        type = types.sctpChunk;
      };
      options.field = mkNullOption {
        description = lib.mdDoc "SCTP chunk field. If this property is not given, the expression is to be used as an SCTP chunk existence check in a **match** statement with a boolean on the right hand side.";
        type = types.sctpChunkField;
      };
    };
    metaExpression = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Meta key.";
        type = types.metaKey;
      };
    };
    rtExpression = submodule' {
      options.key = lib.mkOption {
        description = "Routing data key.";
        type = types.rtKey;
      };
      options.family = mkNullOption {
        description = "Routing data IP family. This property is optional and defaults to unspecified.";
        type = types.ipFamily;
        defaultText = lib.literalExpression null;
      };
    };
    ctExpression = submodule' {
      finalMerge = { key, ... }@ret: let
        info = (ctKeys.${key} or {}).__info__ or {};
        dir = info.dir or null;
        family = info.family or null;
      in
        if dir == true && !ret?dir then throw "You must provide a direction for CT key ${key}."
        else if dir == false && ret?dir then throw "You must not provide a direction for CT key ${key}."
        else if family == true && !ret?family then throw "You must provide an IP family for CT key ${key}."
        else if family == false && ret?family then throw "You must not provide an IP family for CT key ${key}."
        else ret;
      options.key = lib.mkOption {
        description = "CT key";
        type = types.ctKey;
      };
      options.family = mkNullOption {
        description = "IP family.";
        type = types.ipFamily;
      };
      options.dir = mkNullOption {
        description = lib.mdDoc "Some CT keys do not support a direction. In this case, **dir** must not be given.";
        type = types.ctDir;
      };
    };
    numgenExpression = submodule' {
      options.mode = lib.mkOption {
        description = "Numgen mode";
        type = types.ngMode;
      };
      options.mod = lib.mkOption {
        description = "Number modulus (number of different values possible).";
        type = lib.types.int;
      };
      options.offset = mkNullOption {
        description = "Number offset (added to the result). Defaults to 0.";
        type = lib.types.int;
        defaultText = lib.literalExpression 0;
      };
    };
    jhashExpression = submodule' {
      options.mod = lib.mkOption {
        description = "Hash modulus (number of possible different values).";
        type = lib.types.int;
      };
      options.offset = mkNullOption {
        description = "Hash offset (min value). Defaults to 0.";
        type = lib.types.int;
        defaultText = lib.literalExpression 0;
      };
      options.expr = lib.mkOption {
        description = "Expression to hash.";
        type = types.expression;
      };
      options.seed = mkNullOption {
        description = "Hash seed. Defaults to 0.";
        type = lib.types.int;
        defaultText = lib.literalExpression 0;
      };
    };
    symhashExpression = submodule' {
      options.mod = lib.mkOption {
        description = "Hash modulus (number of possible different values).";
        type = lib.types.int;
      };
      options.offset = mkNullOption {
        description = "Hash offset (min value). Defaults to 0.";
        type = lib.types.int;
        defaultText = lib.literalExpression 0;
      };
    };
    fibExpression = submodule' {
      options.result = lib.mkOption {
        description = "Fib expression type.";
        type = types.fibResult;
      };
      options.flags = mkNullOption {
        description = "Fib expression type.";
        type = lib.types.listOf types.fibFlag;
      };
    };
    binOpExpression = lib.types.either (types.listOfSize2 types.expression) (submodule' {
      finalMerge = { left, right }: [ left right ];
      options.left = lib.mkOption {
        description = "Left-hand side of the operation.";
        type = types.expression;
      };
      options.right = lib.mkOption {
        description = "Right-hand side of the operation.";
        type = types.expression;
      };
    });
    elemExpression = submodule' {
      options.val = lib.mkOption {
        description = "Set element.";
        type = types.expression;
      };
      options.timeout = mkNullOption {
        description = lib.mdDoc "Timeout value for sets/maps with flag **timeout**.";
        type = lib.types.int;
      };
      options.expires = mkNullOption {
        description = "The time until given element expires, useful for ruleset replication only.";
        type = lib.types.int;
      };
      options.comment = mkNullOption {
        description = "Per element comment field";
        type = lib.types.str;
      };
    };
    socketExpression = lib.types.submodule {
      options.key = lib.mkOption {
        description = "Socket attribute.";
        type = types.socketKey;
      };
    };
    osfExpression = submodule' {
      options.key = lib.mkOption {
        description = "Which part of the fingerprint info to match against. At this point, only the OS name is supported.";
        type = types.osfKey;
      };
      options.ttl = mkNullOption {
        description = lib.mdDoc "Define how the packet’s TTL value is to be matched. This property is optional. If omitted, the TTL value has to match exactly. A value of **loose** accepts TTL values less than the fingerprint one. A value of **skip** omits TTL value comparison entirely.";
        type = types.osfTtl;
      };
    };
    dslExprHackType = submodule' {
      skipNulls = false;
      finalMerge = x: x.__expr__;
      freeformType = lib.types.unspecified;
      options.__expr__ = lib.mkOption {
        type = types.expression;
      };
    };
    expression = oneOf {
      name = "nftablesExpression";
      description = "nftables expression";
      types = [ lib.types.str lib.types.int lib.types.bool (lib.types.listOf types.expression) types.dslExprHackType ] ++ (lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} expression.\n\n${v.description}";
      })) {
        concat = {
          type = lib.types.listOf types.expression;
          description = "Concatenate several expressions.";
        };
        set = {
          type = types.expression;
          description = "This object constructs an anonymous set. For mappings, an array of arrays with exactly two elements is expected.";
        };
        map = {
          type = types.mapExpression;
          description = "Mapping expression consisting of value/target pairs.";
        };
        prefix = {
          type = types.prefixExpression;
          description = lib.mdDoc "Construct an IPv4 or IPv6 prefix consisting of address part in **addr** and prefix length in **len**.";
        };
        range = {
          type = types.rangeExpression;
          description = "Construct a range of values. The first array item denotes the lower boundary, the second one the upper boundary.";
        };
        payload = {
          type = types.payloadExpression;
          description = lib.mdDoc ''
            Construct a payload expression, i.e. a reference to a certain part of packet data. The first form creates a raw payload expression to point at a number (**len**) of bytes at a certain offset (**offset**) from a given reference point (**base**). The following base values are accepted:

            - **"ll"** - The offset is relative to Link Layer header start offset.
            - **"nh"** - The offset is relative to Network Layer header start offset.
            - **"th"** - The offset is relative to Transport Layer header start offset.

            The second form allows one to reference a field by name (**field**) in a named packet header (**protocol**).
          '';
        };
        exthdr = {
          type = types.exthdrExpression;
          description = lib.mdDoc ''
            Create a reference to a field (**field**) in an IPv6 extension header (**name**). **offset** is used only for **rt0** protocol.

            If the **field** property is not given, the expression is to be used as a header existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
        "tcp option" = {
          type = types.tcpOptionExpression;
          description = lib.mdDoc ''
            Create a reference to a field (**field**) of a TCP option header (**name**).

            If the **field** property is not given, the expression is to be used as a TCP option existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
        "sctp chunk" = {
          type = types.sctpChunkExpression;
          description = ''
            Create a reference to a field (**field**) of an SCTP chunk (name).

            If the **field** property is not given, the expression is to be used as an SCTP chunk existence check in a **match** statement with a boolean on the right hand side.
          '';
        };
        meta = {
          type = types.metaExpression;
          description = "Create a reference to packet meta data.";
        };
        rt = {
          type = types.rtExpression;
          description = lib.mdDoc ''
            Create a reference to packet routing data.

            The **family** property is optional and defaults to unspecified.
          '';
        };
        ct = {
          type = types.ctExpression;
          description = lib.mdDoc ''
            Create a reference to packet conntrack data.

            Some CT keys do not support a direction. In this case, **dir** must not be given.
          '';
        };
        numgen = {
          type = types.numgenExpression;
          description = lib.mdDoc ''
            Create a number generator.

            The **offset** property is optional and defaults to 0.
          '';
        };
        jhash = {
          type = types.jhashExpression;
          description = "Hash packet data (Jenkins Hash).";
        };
        symhash = {
          type = types.symhashExpression;
          description = "Hash packet data (Symmetric Hash).";
        };
        fib = {
          type = types.fibExpression;
          description = "Perform kernel Forwarding Information Base lookups.";
        };
        "|" = {
          type = types.binOpExpression;
          description = "Binary or.";
        };
        "^" = {
          type = types.binOpExpression;
          description = "Binary xor.";
        };
        "&" = {
          type = types.binOpExpression;
          description = "Binary and.";
        };
        "<<" = {
          type = types.binOpExpression;
          description = "Left shift.";
        };
        ">>" = {
          type = types.binOpExpression;
          description = "Right shift.";
        };
        accept = {
          type = types.null;
          description = lib.mdDoc "Same as the **accept** statement, but for use in verdict maps.";
        };
        drop = {
          type = types.null;
          description = lib.mdDoc "Same as the **drop** statement, but for use in verdict maps.";
        };
        continue = {
          type = types.null;
          description = lib.mdDoc "Same as the **continue** statement, but for use in verdict maps.";
        };
        return = {
          type = types.null;
          description = lib.mdDoc "Same as the **return** statement, but for use in verdict maps.";
        };
        jump = {
          type = types.jumpExpression;
          description = lib.mdDoc "Same as the **jump** statement, but for use in verdict maps.";
        };
        goto = {
          type = types.gotoExpression;
          description = lib.mdDoc "Same as the **goto** statement, but for use in verdict maps.";
        };
        elem = {
          type = types.elemExpression;
          description = lib.mdDoc "Explicitly set element object, in case **timeout**, **expires** or **comment** are desired. Otherwise, it may be replaced by the value of **val**.";
        };
        socket = {
          type = types.socketExpression;
          description = "Construct a reference to packet’s socket.";
        };
        osf = {
          type = types.osfExpression;
          description = "";
        };
      });
    };
  };
  wildcard = "\\*";
  setReference = s: "@${s}";
  nftTypes = mkEnum "nftTypes" {
    ipv4_addr.isKey = true;
    ipv6_addr.isKey = true;
    ether_addr.isKey = true;
    inet_proto.isKey = true;
    inet_service.isKey = true;
    mark.isKey = true;
    counter = {};
    quota = {};
  };
  xtTypes = mkEnum "xtTypes" {
    match = {};
    target = {};
    watcher = {};
  };
  payloadBases = mkEnum "payloadBases" {
    ll = {};
    nh = {};
    th = {};
  };
  rtKeys = mkEnum "rtKeys" {
    classid = {};
    nexthop = {};
    mtu = {};
  };
  ctDirs = mkEnum "ctDirs" {
    original = {};
    reply = {};
  };
  ngModes = mkEnum "ngModes" {
    inc = {};
    random = {};
  };
  fibResults = mkEnum "fibResults" {
    # get output interface id
    oif = {};
    # get output interface name
    oifname = {};
    # get output address type
    type = {};
  };
  fibFlags = mkEnum "fibFlags" {
    saddr = {};
    daddr = {};
    mark = {};
    iif = {};
    oif = {};
  };
  socketKeys = mkEnum "socketKeys" {
    transparent = {};
  };
  osfKeys = mkEnum "osfKeys" {
    name = {};
  };
  osfTtl = mkEnum "osfTtl" {
    loose = {};
    skip = {};
  };
  metaKeys = mkEnum "metaKeys" {
    length = {};
    protocol = {};
    priority = {};
    random = {};
    mark = {};
    iif = {};
    iifname = {};
    iiftype = {};
    oif = {};
    oifname = {};
    oiftype = {};
    skuid = {};
    skgid = {};
    nftrace = {};
    rtclassid = {};
    ibriport = {};
    obriport = {};
    ibridgename = {};
    obridgename = {};
    pkttype = {};
    cpu = {};
    iifgroup = {};
    oifgroup = {};
    cgroup = {};
    nfproto = {};
    l4proto = {};
    secpath = {};
  };
  families = mkEnum "families" {
    ip = {
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" ];
      isIp = true;
    };
    ip6 = {
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" ];
      isIp = true;
    };
    inet = {
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" "ingress" ];
    };
    arp = {
      hooks = [ "input" "output" ];
    };
    bridge = {
      # not sure if ingress is supported here, docs dont specify it, whatever
      hooks = [ "prerouting" "input" "forward" "output" "postrouting" "ingress" ];
    };
    netdev = {
      hooks = [ "ingress" "egress" ];
      requireBaseChainDevice = true;
    };
  };
  chainPolicies = mkEnum "chainPolicies" {
    accept = {};
    drop = {};
  };
  setPolicies = mkEnum "setPolicies" {
    performance = {};
    memory = {};
  };
  setFlags = mkEnum "setFlags" {
    constant = {};
    interval = {};
    timeout = {};
  };
  natFlags = mkEnum "natFlags" {
    random = {};
    fully-random = {};
    persistent = {};
  };
  queueFlags = mkEnum "queueFlags" {
    bypass = {};
    fanout = {};
  };
  logLevels = mkEnum "logLevels" {
    emerg = {};
    alert = {};
    crit = {};
    err = {};
    warn = {};
    notice = {};
    info = {};
    debug = {};
    audit = {};
  };
  logFlags = mkEnum "logFlags" {
    "tcp sequence" = {};
    "tcp options" = {};
    "ip options" = {};
    skuid = {};
    ether = {};
    all = {};
  };
  chainTypes = mkEnum "chainTypes" {
    # Standard chain type to use when in doubt.
    filter = { };
    # Chains of this type perform Native Address Translation based on conntrack entries.
    # Only the first packet of a connection actually traverses this chain - its rules
    # usually define details of the created conntrack entry (NAT statements for instance). 
    nat = {
      families = [ "ip" "ip6" "inet" ];
      hooks = [ "prerouting" "input" "output" "postrouting" ];
    };
    # If a packet has traversed a chain of this type and is about to be accepted, a new
    # route lookup is performed if relevant parts of the IP header have changed. This
    # allows one to e.g. implement policy routing selectors in nftables.
    route = {
      families = [ "ip" "ip6" ];
      hooks = [ "output" ];
    };
  };
  hooks = mkEnum "hooks" {
    prerouting = {};
    input = {};
    forward = {};
    output = {};
    postrouting = {};
    ingress = {};
  };
  l4protocols = mkEnum "l4protocols" {
    tcp = { inCtHelper = true; };
    udp = { inCtHelper = true; };
    dccp = {};
    sctp = {};
    gre = {};
    icmpv6 = {};
    icmp = {};
    generic = {};
  };
  l3protocols = mkEnum "l3protocols" {
    ip = {};
    ip6 = {};
    inet = {};
    arp = {};
  };
  timeUnits = mkEnum "timeUnits" {
    second = {};
    minute = {};
    hour = {};
    day = {};
    week = {};
  };
  byteUnits = mkEnum "byteUnits" {
    bytes = {};
    kbytes = {};
    mbytes = {};
    packets = { onlyRate = true; };
  };
  rejectTypes = mkEnum "rejectTypes" {
    icmpx = {};
    icmp = {};
    icmpv6 = {};
    "tcp reset" = {};
  };
  setOperators = mkEnum "setOperators" {
    add = {};
    update = {};
  };
  payloadProtocols = mkEnum "payloadProtocols" {
    ether.fields = [ "daddr" "saddr" "type" ];
    vlan.fields = [ "id" "dei" "pcp" "type" ];
    arp.fields = [ "htype" "ptype" "hlen" "plen" "operation" "saddr ip" "saddr ether" "daddr ip" "daddr ether" ];
    ip.fields = [ "version" "hdrlength" "dscp" "ecn" "length" "id" "frag-off" "ttl" "protocol" "checksum" "saddr" "daddr" ];
    icmp.fields = [ "type" "code" "checksum" "id" "sequence" "gateway" "mtu" ];
    igmp.fields = [ "type" "mrt" "checksum" "group" ];
    ip6.fields = [ "version" "dscp" "ecn" "flowlabel" "length" "nexthdr" "hoplimit" "saddr" "daddr" ];
    icmpv6.fields = [ "type" "code" "checksum" "parameter-problem" "packet-too-big" "id" "sequence" "max-delay" ];
    tcp.fields = [ "sport" "dport" "sequence" "ackseq" "doff" "reserved" "flags" "window" "checksum" "urgptr" ];
    udp.fields = [ "sport" "dport" "length" "checksum" ];
    udplite.fields = [ "sport" "dport" "checksum" ];
    sctp.fields = [ "sport" "dport" "vtag" "checksum" ];
    dccp.fields = [ "sport" "dport" "type" ];
    ah.fields = [ "nexthdr" "hdrlength" "reserved" "spi" "sequence" ];
    esp.fields = [ "spi" "sequence" ];
    comp.fields = [ "nexthdr" "flags" "cpi" ];
    # not sure if "gre ip ..." and "gre ip6 ..." are supported in json scheme
    gre.fields = [ "flags" "version" "protocol" ];
    # same here
    geneve.fields = [ "vni" "flags" ];
    gretap.fields = [ "vni" "flags" ];
    vxlan.fields = [ "vni" "flags" ];
  };
  payloadFields = mkEnum "payloadFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: x.__info__.fields)
        (builtins.attrValues payloadProtocols))));
  exthdrs = mkEnum "exthdrs" {
    hbh.fields = [ "nexthdr" "hdrlength" ];
    rt.fields = [ "nexthdr" "hdrlength" "type" "seg-left" ];
    frag.fields = [ "nexthdr" "frag-off" "more-fragments" "id" ];
    dst.fields = [ "nexthdr" "hdrlength" ];
    mh.fields = [ "nexthdr" "hdrlength" "checksum" "type" ];
    srh.fields = [ "flags" "tag" "sid" "seg-left" ];
  };
  exthdrFields = mkEnum "exthdrFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: x.__info__.fields)
        (builtins.attrValues exthdrs))));
  tcpOptions = mkEnum "tcpOptions" {
    eol.fields = [ ];
    nop.fields = [ ];
    maxseg.fields = [ "length" "size" ];
    window.fields = [ "length" "count" ];
    sack-perm.fields = [ "length" ];
    sack.fields = [ "length" "left" "right" ];
    sack0.fields = [ "length" "left" "right" ];
    sack1.fields = [ "length" "left" "right" ];
    sack2.fields = [ "length" "left" "right" ];
    sack3.fields = [ "length" "left" "right" ];
    timestamp.fields = [ "length" "tsval" "tsecr" ];
  };
  tcpOptionFields = mkEnum "tcpOptionFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: x.__info__.fields)
        (builtins.attrValues tcpOptions))));
  sctpChunks = mkEnum "sctpChunks" {
    data.fields = [ "type" "flags" "length" "tsn" "stream" "ssn" "ppid" ];
    init.fields = [ "type" "flags" "length" "init-tag" "a-rwnd" "num-outbound-streams" "num-inbound-streams" "initial-tsn" ];
    init-ack.fields = [ "type" "flags" "length" "init-tag" "a-rwnd" "num-outbound-streams" "num-inbound-streams" "initial-tsn" ];
    sack.fields = [ "type" "flags" "length" "a-rwnd" "cum-tsn-ack" "num-gap-ack-blocks" "num-dup-tsns" ];
    heartbeat.fields = [ "type" "flags" "length" ];
    heartbeat-ack.fields = [ "type" "flags" "length" ];
    abort.fields = [ "type" "flags" "length" ];
    shutdown.fields = [ "type" "flags" "length" "cum-tsn-ack" ];
    shutdown-ack.fields = [ "type" "flags" "length" ];
    error.fields = [ "type" "flags" "length" ];
    cookie-echo.fields = [ "type" "flags" "length" ];
    cookie-ack.fields = [ "type" "flags" "length" ];
    ecne.fields = [ "type" "flags" "length" "lowest-tsn" ];
    cwr.fields = [ "type" "flags" "length" "lowest-tsn" ];
    shutdown-complete.fields = [ "type" "flags" "length" ];
    asconf-ack.fields = [ "type" "flags" "length" "seqno" ];
    forward-tsn.fields = [ "type" "flags" "length" "new-cum-tsn" ];
    asconf.fields = [ "type" "flags" "length" "seqno" ];
  };
  sctpChunkFields = mkEnum "sctpChunkFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: x.__info__.fields)
        (builtins.attrValues sctpChunks))));
  ctKeys = let
    ff = { dir = false; family = false; }; # false/false
    nf = ff // { dir = null; }; # null/false
    tf = ff // { dir = true; }; # etc
    tt = tf // { family = true; };
  in mkEnum "ctKeys" {
    state = ff;
    direction = ff;
    status = ff;
    mark = ff;
    expiration = ff;
    helper = ff;
    label = ff;
    count = ff;
    id = ff;
    l3proto = nf;
    protocol = nf;
    bytes = nf;
    packets = nf;
    avgpkt = nf;
    zone = nf;
    proto-src = tf;
    proto-dst = tf;
    saddr = tt;
    daddr = tt;
  };
  connectionStates = mkEnum "connectionStates" {
    close.proto = "tcp";
    close_wait.proto = "tcp";
    established.proto = "tcp";
    fin_wait.proto = "tcp";
    last_ack.proto = "tcp";
    retrans.proto = "tcp";
    syn_recv.proto = "tcp";
    syn_sent.proto = "tcp";
    time_wait.proto = "tcp";
    unack.proto = "tcp";
    replied.proto = "udp";
    unreplied.proto = "udp";
  };
  operators = let self = mkEnum "operators" {
    "&" = { };
    "|" = { };
    "^" = { };
    "<<" = { };
    ">>" = { };
    "==" = { };
    "!=" = { };
    "<" = { };
    ">" = { };
    "<=" = { };
    ">=" = { };
    # bitmask
    "in" = { };
  }; in self // {
    # create some aliases
    and = self."&";
    or = self."|";
    xor = self."^";
    lsh = self."<<";
    rsh = self.">>";
    eq = self."==";
    ne = self."!=";
    lt = self."<";
    gt = self.">";
    le = self."<=";
    ge = self.">=";
    IN = self."in";
    in' = self."in";
  };
  priorities = mkEnum "priorities" {
    raw = {
      value = family: -300;
      families = [ "ip" "ip6" "inet" ];
    };
    mangle = {
      value = family: -150;
      families = [ "ip" "ip6" "inet" ];
    };
    dstnat = {
      value = family: if family == "bridge" then -300 else -100;
      families = [ "ip" "ip6" "inet" "bridge" ];
      hooks = [ "prerouting" ];
    };
    filter = {
      value = family: if family == "bridge" then -200 else 0;
      families = [ "ip" "ip6" "inet" "arp" "netdev" "bridge" ];
    };
    security = {
      value = family: 50;
      families = [ "ip" "ip6" "inet" ];
    };
    srcnat = {
      value = family: if family == "bridge" then 300 else 100;
      families = [ "ip" "ip6" "inet" "bridge" ];
      hooks = [ "postrouting" ];
    };
    out = {
      value = family: 100;
      families = [ "bridge" ];
    };
  };
  # tcp_flag
  tcpFlags = builtins.mapAttrs (k: v: k) {
    fin = 1;
    syn = 2;
    rst = 4;
    psh = 8;
    ack = 16;
    urg = 32;
    ecn = 64;
    cwr = 128;
  };
  # fib_addrtype
  fibTypes = builtins.mapAttrs (k: v: k) {
    unspec = 0;
    unicast = 1;
    local = 2;
    broadcast = 3;
    anycast = 4;
    multicast = 5;
    blackhole = 6;
    unreachable = 7;
    prohibit = 8;
  };
  # icmp_type
  icmpTypes = builtins.mapAttrs (k: v: k) {
    echo-reply = 0;
    destination-unreachable = 3;
    source-quench = 4;
    redirect = 5;
    echo-request = 8;
    router-advertisement = 9;
    router-solicitation = 10;
    time-exceeded = 11;
    parameter-problem = 12;
    timestamp-request = 13;
    timestamp-reply = 14;
    info-request = 15;
    info-reply = 16;
    address-mask-request = 17;
    address-mask-reply = 18;
  };
  icmpv6Types = builtins.mapAttrs (k: v: k) {
    destination-unreachable = 1;
    packet-too-big = 2;
    time-exceeded = 3;
    parameter-problem = 4;
    echo-request = 128;
    echo-reply = 129;
    mld-listener-query = 130;
    mld-listener-report = 131;
    mld-listener-done = 132;
    mld-listener-reduction = 132;
    nd-router-solicit = 133;
    nd-router-advert = 134;
    nd-neighbor-solicit = 135;
    nd-neighbor-advert = 136;
    nd-redirect = 137;
    router-renumbering = 138;
    ind-neighbor-solicit = 141;
    ind-neighbor-advert = 142;
    mld2-listener-report = 143;
  };
  ctStates = builtins.mapAttrs (k: v: k) {
    invalid = 1;
    established = 2;
    related = 4;
    new = 8;
    untracked = 64;
  };
  exists = true;
  missing = false;
in rec {
  config.notnft = {
    inherit families chainTypes types wildcard setReference payloadBases payloadProtocols payloadFields exthdrs exthdrFields tcpOptions tcpOptionFields sctpChunks sctpChunkFields metaKeys rtKeys ctKeys ctDirs ngModes fibResults fibFlags socketKeys osfKeys osfTtl priorities hooks chainPolicies nftTypes setPolicies setFlags operators tcpFlags fibTypes exists missing icmpTypes icmpv6Types timeUnits ctStates;
    dsl = import ./dsl.nix { inherit (config) notnft; inherit lib; };
  };
  options.notnftConfig.enumMode = lib.mkOption {
    default = "normal";
    type = lib.types.str;
    description = lib.mdDoc ''
      Enum mode. "strict" to disallow using strings, "normal" for default behavior, "lax" to disable enum checks.
    '';
  };
}
